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
    #[arg(short, long, default_value_t = 50)]
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
    pub resolver: Resolver<TokioConnectionProvider>,
    pub cdn_cnames: Arc<Vec<String>>
}

impl AppContext {
    pub fn build() -> Result<Self, Box<dyn Error>> {
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

        let mut config = ResolverConfig::new();
        config.add_name_server(NameServerConfig::new(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(223, 5, 5, 5)), 53),
            Protocol::Udp
        ));

        let mut options = ResolverOpts::default();
        options.timeout = Duration::from_secs(2);
        options.attempts = 1;

        let resolver = Resolver::builder_with_config(
            config,
            TokioConnectionProvider::default()
        )
        .with_options(options)
        .build();

        Ok(Self {
            domain: args.domain,
            wordlist,
            threads: args.threads,
            resolver,
            cdn_cnames: Arc::new(cdn_cnames),
        })
    }

    pub async fn detect_wildcard(&self) -> HashSet<IpAddr> {
        let mut wildcard_ips: HashSet<IpAddr> = HashSet::new();
        let fake_domain = format!("this-is-fake-wildcard-test-999.{}", self.domain);

        if let Ok(ips) = self.resolver.lookup_ip(&fake_domain).await {
            for ip in ips.iter() {
                wildcard_ips.insert(ip);
            }
        }

        wildcard_ips
    }
}



#[tokio::main]
async fn main() {

    let ctx = match AppContext::build() {
        Ok(c) => c,
        Err(e) => {
            println!("Inition failed: {}", e);
            std::process::exit(1);
        }
    };

    if let Err(e) = ctx.resolver.lookup_ip("www.baidu.com").await {
        println!("DNS lookup failed: {}", e);
        println!("Please check your network setting.");
        std::process::exit(1);
    }

    let wildcard_ips: HashSet<IpAddr> = ctx.detect_wildcard().await;
    let wildcard_ips_shared = Arc::new(wildcard_ips);

    let lookups = stream::iter(ctx.wordlist.clone()).map(|subdomain| {
        let r = ctx.resolver.clone();
        let target = format!("{}.{}", subdomain, ctx.domain);

        let cdn_list = Arc::clone(&ctx.cdn_cnames);
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

    let mut stream = lookups.buffer_unordered(ctx.threads);
    let mut found_flag = false;

    let total_tasks = ctx.wordlist.len() as u64;
    let pb = ProgressBar::new(total_tasks);

    pb.set_style(
        ProgressStyle::with_template(
            "[{elapsed_precise}] {bar:40.cyan/blue} {pos}/{len} ({eta}) | {per_sec}"
        )
        .unwrap()
        .progress_chars("##-")
    );

    while let Some((domain, res_ip, is_wild, is_cdn)) = stream.next().await {
        pb.inc(1);
        
        if is_wild { continue; }

        if let Ok(ips) = res_ip  {
            found_flag = true;

            let ip_list: Vec<String> = ips.iter().map(|ip| ip.to_string()).collect();

            let colored_ips = ip_list.iter()
            .map(|ip| ip.green().to_string())
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