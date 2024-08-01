# Tonutils Reverse Proxy

[![Based on TON][ton-svg]][ton]
[![Telegram Channel][tgc-svg]][tg-channel]

Easy to set up and use reverse proxy for TON Sites.
It makes your website accessible inside The Open Network!

### Install

Using linux based server:
```sh
wget https://github.com/ton-utils/reverse-proxy/releases/latest/download/tonutils-reverse-proxy-linux-amd64
chmod +x tonutils-reverse-proxy-linux-amd64
```

Or download a binary for your OS:
   * [Linux AMD64](https://github.com/ton-utils/reverse-proxy/releases/latest/download/tonutils-reverse-proxy-linux-amd64)
   * [Linux ARM64](https://github.com/ton-utils/reverse-proxy/releases/latest/download/tonutils-reverse-proxy-linux-arm64)
   * [Windows x64](https://github.com/ton-utils/reverse-proxy/releases/latest/download/tonutils-reverse-proxy-windows-x64.exe)
   * [Mac Intel](https://github.com/ton-utils/reverse-proxy/releases/latest/download/tonutils-reverse-proxy-mac-amd64)
   * [Mac Apple Silicon](https://github.com/ton-utils/reverse-proxy/releases/latest/download/tonutils-reverse-proxy-mac-arm64) 

### Run

Run with domain configuration, and follow the steps:

```sh
./tonutils-reverse-proxy-linux-amd64 --domain your-domain.ton 
```

<img width="500" alt="yes1" src="https://user-images.githubusercontent.com/9332353/210967656-182b0d0f-6954-49c9-bf8a-40f5b4a61aa7.png">

Scan QR code from your terminal using Tonkeeper, Tonhub or any other wallet, execute transaction. Your domain will be linked to your site. 

If for some reason you cannot scan QR code, add `-tx-url` flag, so it will be displayed as `ton://` url for transaction.

##### Run without domain

Alternatively, you can run in simple mode, with .adnl domain, if you don't have .ton or .t.me domain:

```sh
./tonutils-reverse-proxy-linux-amd64
```

##### Use

Now anyone can access your TON Site! Using ADNL address or domain. 

If you want to change some settings, like proxy pass url - open `config.json` file, edit and restart proxy. Default proxy pass url is `http://127.0.0.1:80/`

Proxy adds additional headers:
`X-Adnl-Ip` - ip of client, and `X-Adnl-Id` - adnl id of client

### FAQ

#### Can I have multiple domains on single reverse-proxy?

Yes! You can run any number of sites within single reverse-proxy, just link all your domains to same ADNL address. 
You can run reverse-proxy with `-domain` flag one by one for all your domains and execute transaction. `-domain` flag is needed only for linking step, for further launches you are not required to specify it, your domains will remain linked.

#### I'm getting error code 651: too big masterchain block seqno

It can be due to public liteservers synchronization issues, you can replace global config url in `config.json` to tonutils liteservers config `https://tonutils.com/ls/free-mainnet-config.json`, or any other.

#### My TON Site is not working in Telegram, and before I've used older reverse proxy version

It can be because of older protocol data time was cached by Telegram proxy, the fastest way to recover is regenerate ADNL address, just delete `config.json` and relink your domain to newly generated ADNL ID.

#### I started reverse proxy but my site is not responding

To run TON Site you should have public (white) ip address, and in+out UDP traffic allowed on port from `config.json`. You could use [Tonutils Proxy](https://github.com/xssnick/Tonutils-Proxy) to check your site.

### How to build from sources

Build it from sources using `make build`, and run as in the step 2 for linux. Go environment is required to build.

<!-- Badges -->
[ton-svg]: https://img.shields.io/badge/Based%20on-TON-blue
[tgc-svg]: https://img.shields.io/badge/Telegram%20-Subscribe-24A1DE

[ton]: https://ton.org
[tg-channel]: https://t.me/tonutilsnews
