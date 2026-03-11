use std::ops::Deref;
use std::time::Duration;
use std::collections::HashSet;
use std::error::Error;
use std::sync::Arc;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::fmt;
use hickory_proto::{rr::record_type::RecordType, xfer::Protocol};
use hickory_resolver::{config::*, Resolver, name_server::TokioConnectionProvider};
use futures::{stream::{self, StreamExt}, io};
use clap::Parser;
use colored::Colorize;
use indicatif::{ProgressBar, ProgressStyle};
use rand::distr::{Alphanumeric, SampleString};
use tokio::io::{AsyncWriteExt, BufWriter};

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

async fn detect_wildcard(resolvers: &[Resolver<TokioConnectionProvider>], domain: &str) -> HashSet<Subnet> {
        let mut tasks = Vec::new();
        for _ in 0..5 {
            let fake_sub = Alphanumeric.sample_string(&mut rand::rng(), 8);
            let fake_domain = format!("{}.{}", fake_sub, domain);

            for resolver in resolvers {
                tasks.push((resolver, fake_domain.clone()));

            }
        }

        let lookups = stream::iter(tasks).map(|(r, d)| {
            async move {
                let mut subnets = Vec::new();
                if let Ok(ips) = r.lookup_ip(&d).await {
                    for ip in ips.iter() {
                        subnets.push(Subnet::from_ip(&ip));
                    }
                }

                if let Ok(ipv6s) = r.lookup(&d, RecordType::AAAA).await {
                    for ipv6 in ipv6s.iter() {
                        if let Some(ipv6) = ipv6.as_aaaa() {
                            subnets.push(Subnet::from_ip(&ipv6.0.into()));
                        }
                    }
                }
                subnets
            }
        });

        let mut streams = lookups.buffer_unordered(80);
        let mut wildcard_ips: HashSet<Subnet> = HashSet::new();

        while let Some(subnets) = streams.next().await {
            for subnet in subnets {
                wildcard_ips.insert(subnet);
            }
        }

        wildcard_ips
}

#[derive(Debug, Eq, Hash, PartialEq)]
pub enum Subnet {
    V4([u8; 3]),
    V6([u16; 4])
}

impl Subnet {
    pub fn from_ip(ip: &IpAddr) -> Self {
        match ip {
            IpAddr::V4(ip) => {
                let ip_parts = ip.octets();
                Subnet::V4([ip_parts[0], ip_parts[1], ip_parts[2]])
            },
            IpAddr::V6(ip) => {
                let ip_parts = ip.segments();
                Subnet::V6([ip_parts[0], ip_parts[1], ip_parts[2], ip_parts[3]])
            }
        }
    }
}

impl fmt::Display for Subnet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Subnet::V4(parts) => {
                write!(f, "{}.{}.{}.0/24", parts[0], parts[1], parts[2])
            }
            Subnet::V6(parts) => {
                write!(f, "{:x}:{:x}:{:x}:{:x}::/64", parts[0], parts[1], parts[2], parts[3])
            }
        }
    }
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
            options.timeout = Duration::from_millis(1200);
            options.attempts = 2;

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

}



#[tokio::main]
async fn main() {
    println!("{} InitInitializing...", "[*]".blue());

    let (ctx, dns_servers) = match AppContext::build().await {
        Ok(res) => res,
        Err(e) => {
            println!("Inition failed: {}", e);
            std::process::exit(1);
        }
    };

    let AppContext {
        domain,
        wordlist,
        threads,
        resolvers,
        cdn_cnames,
    } = ctx;

    let total_tasks = wordlist.len() as u64;
    let pb = ProgressBar::new(total_tasks);
    pb.set_style(
        ProgressStyle::with_template(
            "[{elapsed_precise}] {bar:40.cyan/blue} {pos}/{len} ({eta}) | {per_sec}"
        )
        .unwrap()
        .progress_chars("#>-")
    );

    let wildcard_ips: HashSet<Subnet> = detect_wildcard(&resolvers.deref(), &domain).await;
    if !wildcard_ips.is_empty() {
        println!("{} Wildcard IPs:", "[!]".yellow());
        
        for subnet in &wildcard_ips {
            println!("    - {}", subnet.to_string().yellow()); 
        }
    }
    pb.println(format!("Available DNS servers: {}", dns_servers.join(", ").green()));


    let wildcard_ips_shared = Arc::new(wildcard_ips);
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

            if let Ok(ips) = res_ip.as_ref() {
                is_wild = ips.iter().any(|ip| wildcard.contains(&Subnet::from_ip(&ip)));
            }

            if !is_wild {
                if let Ok(res_cname) = r.lookup(target.clone(), RecordType::CNAME).await {
                    is_cdn = res_cname.iter().any(|cname| {
                        let cname = cname.to_string();
                        cdn_list.iter().any(|cdn_cname| cname.contains(cdn_cname) )
                    });
                }
            }

            (target, res_ip, is_wild, is_cdn)
        }
    });

    let mut stream = lookups.buffer_unordered(threads);
    let mut found_flag = false;

    let suspect_file = tokio::fs::File::create("wildcard_suspects.txt").await.expect("Failed to create wildcard file");
    let mut suspect_writer = BufWriter::new(suspect_file);

    while let Some((domain, res_ip, is_wild, is_cdn)) = stream.next().await {
        pb.inc(1);

        if let Ok(ips) = res_ip  {
            if is_wild {
                let ip_strs = ips.iter().map(|ip| ip.to_string()).collect::<Vec<_>>().join(",");
                let line = format!("{} [{}]\n", domain, ip_strs);
                    
                suspect_writer.write_all(line.as_bytes()).await.unwrap();
                continue;
            }
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

    pb.println("The suspected wildcard DNS subdomain is stored in wildcard_suspects.txt.".blue().to_string());
    pb.finish_and_clear();

    if !found_flag { println!("{}", "No subdomains discovered, or all resolved to wildcard IPs. ".red()) }
}