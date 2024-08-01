# Tonutils Reverse Proxy
Easy to set up and use reverse proxy for TON Sites.
It makes your website accessible via TON Network!

### Installation on any Linux

##### Download

```sh
wget https://github.com/ton-utils/reverse-proxy/releases/download/v0.3.3/tonutils-reverse-proxy-linux-amd64
chmod +x tonutils-reverse-proxy-linux-amd64
```

Builds for other operation systems are also available on release page.

##### Run

Run with domain configuration, and follow the steps:

```sh
./tonutils-reverse-proxy-linux-amd64 --domain your-domain.ton 
```

<img width="500" alt="yes1" src="https://user-images.githubusercontent.com/9332353/210967656-182b0d0f-6954-49c9-bf8a-40f5b4a61aa7.png">

Scan QR code from your terminal using Tonkeeper, Tonhub or any other wallet, execute transaction. Your domain will be linked to your site. 

If for some reason you cannot scan QR code, add `-tx-url` flag, so it will be displayed as `ton://` url for transaction.

###### Run without domain

Alternatively, you can run in simple mode, with .adnl domain, if you don't have .ton or .t.me domain:

```sh
./tonutils-reverse-proxy-linux-amd64
```

##### Use

Now anyone can access your TON Site! Using ADNL address or domain. 

If you want to change some settings, like proxy pass url - open `config.json` file, edit and restart proxy. Default proxy pass url is `http://127.0.0.1:80/`

Proxy adds additional headers:
`X-Adnl-Ip` - ip of client, and `X-Adnl-Id` - adnl id of client

### Installation on any other OS

Build it from sources using `make build`, and run as in the step 2 for linux. Go environment is required to build.
