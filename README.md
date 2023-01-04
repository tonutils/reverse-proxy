# TonUtils Reverse Proxy
Easy to set up and use reverse proxy for TON Sites.
It allows to make your website accessible via TON Network!


### Installation on any Linux
##### Download
```bash
wget ...tonutils-reverse-proxy
```

##### Run

With domain configuration:
```
./tonutils-reverse-proxy --domain your-domain.ton 
```

Or simple mode, with .adnl domain, if you don't have .ton or .t.me domain:
```
./tonutils-reverse-proxy --domain your-domain.ton 
```

### Installation on any other OS

Build it from sources `go build`, and run as in the step 2 for linux.