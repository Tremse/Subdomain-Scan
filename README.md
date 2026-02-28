# Subdomain-Scan

一个由 Rust 编写的高并发子域名扫描器

## Features

- 基于 DNS 查询的子域名扫描
- 自动排除泛解析导致的"误报"
- 能够标识出存在CDN的目标
- 通过进度条实时显示进度
- 通过 DNS 池来分散查询, 增加了大字典情况下的速率

## Building it yourself

```bash
git clone git@github.com:Tremse/Subdomain-Scan.git
cd Subdomain-Scan
cargo build --release
```

生成的二进制文件位于 ./target/release/subdomain-scan

本项目带有测试用字典, 其来源于 **SecLists**

 感谢 [Daniel Miessler](https://github.com/danielmiessler) 维护的开源项目 **SecLists**: [https://github.com/danielmiessler/SecLists](https://github.com/danielmiessler/SecLists)

## Usage

命令行参数:

```
Usage: subdomain-scan [OPTIONS] --domain <DOMAIN> --wordlist <WORDLIST>

Options:
  -d, --domain <DOMAIN>      Target root domain
  -w, --wordlist <WORDLIST>  Path to the wordlist file
  -t, --threads <THREADS>    Number of concurrent tasks/lookups [default: 50]
  -h, --help                 Print help
  -V, --version              Print version
```

## Example

```bash
subdomain-scan -d example.com -w  ./dict/subdomains-dict.txt

[+] www.example.com           -> [104.18.27.120 | 104.18.26.120]
```

## Powered by

- [tokio](https://github.com/tokio-rs/tokio)
- [hickory-dns](https://github.com/hickory-dns/hickory-dns)
- [indicatif](https://github.com/console-rs/indicatif)
- [colored](https://github.com/colored-rs/colored)
- [clap](https://github.com/clap-rs/clap)
- [futures](https://github.com/rust-lang/futures-rs)

