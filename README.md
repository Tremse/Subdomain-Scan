# Subdomain-Scan

一个由 Rust 编写的高并发子域名扫描器

## Features

- 基于 DNS 查询的子域名扫描
- 自动排除泛解析导致的"误报"
- 能够标识出存在CDN的目标
- 通过进度条实时显示进度

## Building it yourself

```bash
git clone git@github.com:Tremse/Subdomain-Scan.git
cd Subdomain-Scan
cargo build --release
```

生成的二进制文件位于 ./target/release/subdomain-scan

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

