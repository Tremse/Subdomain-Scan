use futures::io;
use hickory_proto::rr::record_type::RecordType;
use hickory_resolver::config::*;
use hickory_resolver::Resolver;
use hickory_resolver::name_server::TokioConnectionProvider;
use std::time::Duration;
use futures::stream::{self, StreamExt};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use hickory_proto::xfer::Protocol;
use std::path::Path;
use std::fs::File;
use std::io::{BufRead, BufReader};
use clap::Parser;
use std::collections::HashSet;
use std::error::Error;
use std::sync::Arc;
use colored::Colorize;
use indicatif::{ProgressBar, ProgressStyle};

#[derive(Parser, Debug)] 
#[command(author, version, about = "subdomain-scan BETA", long_about = None)]
struct Args {
    /// Target root domain
    #[arg(short, long)]
    domain: String,

    /// Path to the wordlist file
    #[arg(short, long)]
    wordlist: String,

    /// Number of concurrent tasks/lookups
    #[arg(short, long, default_value_t = 500)]
    threads: usize,
}

fn wordlist_load<T: AsRef<Path>>(filename: T) -> io::Result<Vec<String>> {
    let file = File::open(filename)?;
    let reader = BufReader::new(file);
    let mut wordlist = Vec::new();
    for line in reader.lines() {
        let line = line?;
        let line = line.trim();
        if !line.is_empty() && !line.starts_with("#") {
            wordlist.push(line.to_string());
        }
    }
    Ok(wordlist)
}

pub struct AppContext {
    pub domain: String,
    pub wordlist: Vec<String>,
    pub threads: usize,
    pub resolvers: Vec<Resolver<TokioConnectionProvider>>,
    pub cdn_cnames: Arc<Vec<String>>
}

impl AppContext {
    pub async fn build() -> Result<(Self, Vec<&'static str>), Box<dyn Error>> {
        let cdn_cnames = vec![
            "cloudflare.net", "cloudflare.com",
            "cloudfront.net",
            "kunlunpi.com", "kunlunca.com", "aliyuncs.com",
            "tencent-cloud.net", "qcloud.com", "cdntip.com",
            "akamai.net", "akamaihd.net", "edgesuite.net",
            "fastly.net",
            "cdn20.com", "w.cdngslb.com",
            "bdydns.com", "jiasule.com",
        ].iter().map(|s| s.to_string()).collect();

        let args = Args::parse();

        let wordlist = wordlist_load(&args.wordlist)?;
        if wordlist.is_empty() {
            return Err("Dictory empty".into());
        }

        let dns_servers = vec![
            ("Ali-DNS", (223, 5, 5, 5)),
            ("Tencent-Dns", (119, 29, 29, 29)),
            ("114-DNS", (114, 114, 114, 114)),
            ("Google", (8, 8, 8, 8)),
            ("CloudFlare", (1, 1, 1, 1)),
            ("Quad9", (9, 9, 9, 9)),
            ("Baidu-DNS", (180, 76, 76, 76))
        ];

        let mut resolvers_tmp = Vec::new();

        for (s, (a, b, c, d)) in dns_servers {
            let mut config = ResolverConfig::new();
            config.add_name_server(NameServerConfig::new(
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(a, b, c, d)), 53),
                Protocol::Udp
            ));

            let mut options = ResolverOpts::default();
            options.timeout = Duration::from_millis(1000);
            options.attempts = 1;

            let resolver = Resolver::builder_with_config(
                config,
                TokioConnectionProvider::default()
            )
            .with_options(options)
            .build();

            resolvers_tmp.push((s, resolver));
        }
        
        let cheak_stream = stream::iter(resolvers_tmp).map(|(s, r)| {
            async move {
                let start = std::time::Instant::now();
                match r.lookup_ip("example.com").await {
                    Ok(_) => {
                        let elapsed = start.elapsed();
                        if elapsed.as_millis() > 150 {
                            None
                        } else {
                            Some((s, r))
                        }
                    },
                    Err(_) => {
                        None
                    }
                }
            }
        });

        let mut resolvers = Vec::new();
        let mut active_dns = Vec::new();
        let mut results = cheak_stream.buffer_unordered(8);

        while let Some(res) = results.next().await {
            if let Some((s, r)) = res {
                resolvers.push(r);
                active_dns.push(s);
            }
        }

        if active_dns.is_empty() {
            return Err("No DNS Server is aviliable now! Check your network.".into());
        }

        Ok((
            Self {
            domain: args.domain,
            wordlist,
            threads: args.threads,
            resolvers,
            cdn_cnames: Arc::new(cdn_cnames),
            },
            active_dns
        ))
    }

    pub async fn detect_wildcard(&self) -> HashSet<IpAddr> {
        let mut wildcard_ips: HashSet<IpAddr> = HashSet::new();
        let fake_domain = format!("this-is-fake-wildcard-test-999.{}", self.domain);

        if let Ok(ips) = self.resolvers[0].lookup_ip(&fake_domain).await {
            for ip in ips.iter() {
                wildcard_ips.insert(ip);
            }
        }

        wildcard_ips
    }
}



#[tokio::main]
async fn main() {

    let (ctx, dns_servers) = match AppContext::build().await {
        Ok(res) => res,
        Err(e) => {
            println!("Inition failed: {}", e);
            std::process::exit(1);
        }
    };

    let wildcard_ips: HashSet<IpAddr> = ctx.detect_wildcard().await;
    let wildcard_ips_shared = Arc::new(wildcard_ips);

    let total_tasks = ctx.wordlist.len() as u64;
    let pb = ProgressBar::new(total_tasks);
    pb.set_style(
        ProgressStyle::with_template(
            "[{elapsed_precise}] {bar:40.cyan/blue} {pos}/{len} ({eta}) | {per_sec}"
        )
        .unwrap()
        .progress_chars("##-")
    );
    pb.println(format!("Available DNS servers: {}", dns_servers.join(", ").green()));

    let AppContext {
        domain,
        wordlist,
        threads,
        resolvers,
        cdn_cnames,
    } = ctx;

    let pool_size = resolvers.len();
    let lookups = stream::iter(wordlist.into_iter().enumerate()).map(move |(index, subdomain)| {
        let r = resolvers[index%pool_size].clone();
        let target = format!("{}.{}", subdomain, domain);

        let cdn_list = Arc::clone(&cdn_cnames);
        let wildcard = Arc::clone(&wildcard_ips_shared);

        async move {
            let mut is_wild= false;
            let mut is_cdn = false;

            let res_ip = r.lookup_ip(target.clone()).await;

            if let Ok(ips) = res_ip.clone() {
                is_wild = ips.iter().any(|ip| wildcard.contains(&ip));
            }

            if !is_wild {
                if let Ok(res_cname) = r.lookup(target.clone(), RecordType::CNAME).await {
                    is_cdn = res_cname.iter().any(|cname| {
                        cdn_list.iter().any(|cdn_cname| cname.to_string().contains(cdn_cname) )
                    });
                }
            }

            (target, res_ip, is_wild, is_cdn)
        }
    });

    let mut stream = lookups.buffer_unordered(threads);
    let mut found_flag = false;

    while let Some((domain, res_ip, is_wild, is_cdn)) = stream.next().await {
        pb.inc(1);
        
        if is_wild { continue; }

        if let Ok(ips) = res_ip  {
            found_flag = true;

            let colored_ips = ips.iter()
            .map(|ip| ip.to_string().green().to_string())
            .collect::<Vec<String>>()
            .join(&" | ".white().to_string());

            pb.println(format!("{} {:<25} -> {}[{}]", 
                "[+]".green(), 
                domain, 
                if is_cdn { "[CDN] ".yellow() } else { "".normal() }, 
                colored_ips
            ));
        }
    }

    pb.finish_and_clear();

    if !found_flag { println!("{}", "No subdomain found.".red()) }
}