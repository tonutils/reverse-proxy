# TonUtils Reverse Proxy
Easy to set up and use reverse proxy for TON Sites.
It allows to make your website accessible via TON Network!


### Installation on any Linux
##### Download
```bash
wget https://github.com/ton-utils/reverse-proxy/releases/download/v0.0.1/tonutils-reverse-proxy-linux-amd64
chmod 777 tonutils-reverse-proxy-linux-amd64
```

##### Run

Run with domain configuration, and follow the steps:
```
./tonutils-reverse-proxy-linux-amd64 --domain your-domain.ton 
```

Or run in simple mode, with .adnl domain, if you don't have .ton or .t.me domain:
```
./tonutils-reverse-proxy-linux-amd64 --domain your-domain.ton 
```

##### Use
Now anyone can access your TON Site! Using ADNL address or domain. 

If you want to change some settings, like proxy pass url - open `config.json` file, edit and restart proxy. Default proxy pass url is `http://127.0.0.1:80/`

### Installation on any other OS

Build it from sources using `./build.sh`, and run as in the step 2 for linux. Go environment is required to build.
