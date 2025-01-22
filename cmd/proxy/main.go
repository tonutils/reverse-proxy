package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"time"

	"github.com/mdp/qrterminal/v3"
	"github.com/sigurn/crc16"
	"github.com/ton-utils/reverse-proxy/config"
	"github.com/xssnick/tonutils-go/adnl"
	"github.com/xssnick/tonutils-go/adnl/dht"
	"github.com/xssnick/tonutils-go/adnl/rldp"
	rldphttp "github.com/xssnick/tonutils-go/adnl/rldp/http"
	"github.com/xssnick/tonutils-go/liteclient"
	"github.com/xssnick/tonutils-go/tlb"
	"github.com/xssnick/tonutils-go/ton"
	"github.com/xssnick/tonutils-go/ton/dns"
)

type Config struct {
	ProxyPass        string `json:"proxy_pass"`
	PrivateKey       []byte `json:"private_key"`
	ExternalIP       string `json:"external_ip"`
	ListenIP         string `json:"listen_ip"`
	NetworkConfigURL string `json:"network_config_url"`
	Port             uint16 `json:"port"`
}

var FlagDomain = flag.String("domain", "", "domain to configure")
var FlagDebug = flag.Bool("debug", false, "more logs")
var FlagTxURL = flag.Bool("tx-url", false, "show set domain record url instead of qr")
var FlagPort = flag.Uint("port", 0, "port of adnl server")
var FlagProxyPass = flag.String("proxy-pass", "http://127.0.0.1:80/", "entry point of your webserver")
var GitCommit = "custom"
var Version = "v0.3.3"

type Handler struct {
	h http.Handler
}

func (h Handler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if *FlagDebug {
		reqDump, err := httputil.DumpRequestOut(request, true)
		if err != nil {
			return
		}
		fmt.Println("REQUEST:", string(reqDump))
	}

	hdr := http.Header{}
	for k := range request.Header {
		// make headers canonical
		for _, s := range request.Header.Values(k) {
			hdr.Add(k, s)
		}
	}
	request.Header = hdr

	log.Println("request:", request.Method, request.Host, request.RequestURI)

	writer.Header().Set("Ton-Reverse-Proxy", "Tonutils Reverse Proxy "+Version)
	h.h.ServeHTTP(writer, request)
}

func main() {
	flag.Parse()

	log.Println("Tonutils Reverse Proxy", Version+", build: "+GitCommit)

	cfg, err := loadConfig()
	if err != nil {
		panic("failed to load config: " + err.Error())
	}

	netCfg, err := liteclient.GetConfigFromUrl(context.Background(), cfg.NetworkConfigURL)
	if err != nil {
		log.Println("failed to download ton config:", err.Error(), "; we will take it from static cache")
		netCfg = &liteclient.GlobalConfig{}
		if err = json.NewDecoder(bytes.NewBufferString(config.FallbackNetworkConfig)).Decode(netCfg); err != nil {
			log.Println("failed to parse fallback ton config:", err.Error())
			os.Exit(1)
		}
	}

	client := liteclient.NewConnectionPool()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	err = client.AddConnectionsFromConfig(ctx, netCfg)
	if err != nil {
		panic(err)
	}

	_, dhtAdnlKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		panic("failed to generate ed25519 key for dht: " + err.Error())
	}

	gateway := adnl.NewGateway(dhtAdnlKey)
	err = gateway.StartClient()
	if err != nil {
		panic("failed to load network config: " + err.Error())
	}

	dhtClient, err := dht.NewClientFromConfig(gateway, netCfg)
	if err != nil {
		panic(err)
	}

	u, err := url.Parse(cfg.ProxyPass)
	if err != nil {
		panic(err)
	}

	if *FlagDebug == false {
		adnl.Logger = func(v ...any) {}
		rldphttp.Logger = func(v ...any) {}
	} else {
		rldp.Logger = log.Println
		rldphttp.Logger = log.Println
		adnl.Logger = log.Println
	}

	proxy := httputil.NewSingleHostReverseProxy(u)
	s := rldphttp.NewServer(ed25519.NewKeyFromSeed(cfg.PrivateKey), dhtClient, Handler{proxy})
	s.SetExternalIP(net.ParseIP(cfg.ExternalIP).To4())

	addr, err := rldphttp.SerializeADNLAddress(s.Address())
	if err != nil {
		panic(err)
	}
	log.Println("Server's ADNL address is", addr+".adnl ("+hex.EncodeToString(s.Address())+")")

	if *FlagDomain != "" {
		setupDomain(client, *FlagDomain, s.Address())
	}

	log.Println("Starting server on", addr+".adnl")
	if err = s.ListenAndServe(fmt.Sprintf("%s:%d", cfg.ListenIP, cfg.Port)); err != nil {
		panic(err)
	}
}

func getPublicIP() (string, error) {
	req, err := http.Get("http://ip-api.com/json/")
	if err != nil {
		return "", err
	}
	defer req.Body.Close()

	body, err := io.ReadAll(req.Body)
	if err != nil {
		return "", err
	}

	var ip struct {
		Query string
	}
	err = json.Unmarshal(body, &ip)
	if err != nil {
		return "", err
	}

	return ip.Query, nil
}

func loadConfig() (*Config, error) {
	var cfg Config

	file := "./config.json"
	data, err := os.ReadFile(file)
	if err != nil {
		var srvKey ed25519.PrivateKey
		_, srvKey, err = ed25519.GenerateKey(nil)
		if err != nil {
			return nil, err
		}
		cfg.PrivateKey = srvKey.Seed()
		cfg.NetworkConfigURL = "https://ton.org/global.config.json"

		cfg.ExternalIP, err = getPublicIP()
		if err != nil {
			return nil, err
		}
		cfg.ListenIP = "0.0.0.0"

		if FlagPort != nil && *FlagPort > 0 {
			// generate consistent port
			cfg.Port = uint16(*FlagPort)
		} else {
			// generate consistent port
			cfg.Port = 9000 + (crc16.Checksum([]byte(cfg.ExternalIP), crc16.MakeTable(crc16.CRC16_XMODEM)) % 5000)
		}

		cfg.ProxyPass = *FlagProxyPass

		data, err = json.MarshalIndent(cfg, "", "\t")
		if err != nil {
			return nil, err
		}

		err = os.WriteFile(file, data, 0644) // rw-r--r--
		if err != nil {
			return nil, err
		}

		return &cfg, nil
	}

	err = json.Unmarshal(data, &cfg)
	if err != nil {
		return nil, err
	}

	// backwards compatibility with old configs
	if cfg.NetworkConfigURL == "" {
		cfg.NetworkConfigURL = "https://ton.org/global.config.json"
	}

	return &cfg, nil
}

func setupDomain(client *liteclient.ConnectionPool, domain string, adnlAddr []byte) {
	ctx := client.StickyContext(context.Background())
	// initialize ton api lite connection wrapper
	api := ton.NewAPIClient(client)

	// get root dns address from network config
	root, err := dns.GetRootContractAddr(ctx, api)
	if err != nil {
		log.Println("Failed to resolve root dns contract:", err)
		return
	}

	resolver := dns.NewDNSClient(api, root)
	domainInfo, err := resolver.Resolve(ctx, domain)
	if err != nil {
		log.Println("Failed to configure domain", domain, ":", err)
		return
	}

	record, isStorage := domainInfo.GetSiteRecord()
	if isStorage || !bytes.Equal(record, adnlAddr) {
		data := domainInfo.BuildSetSiteRecordPayload(adnlAddr, false).ToBOCWithFlags(false)
		args := "?bin=" + base64.URLEncoding.EncodeToString(data) + "&amount=" + tlb.MustFromTON("0.02").Nano().String()

		nftData, err := domainInfo.GetNFTData(ctx)
		if err != nil {
			log.Println("Failed to get domain data", domain, ":", err)
			return
		}

		txUrl := "ton://transfer/" + domainInfo.GetNFTAddress().String() + args
		if *FlagTxURL {
			fmt.Println(txUrl)
		} else {
			qrterminal.GenerateHalfBlock(txUrl, qrterminal.L, os.Stdout)
		}
		fmt.Println("Execute this transaction from the domain owner's wallet to setup site records.")
		fmt.Println("Execute transaction from wallet:", nftData.OwnerAddress.String())
		fmt.Println("When you've done, configuration will automatically proceed in ~10 seconds.")
		for {
			time.Sleep(2 * time.Second)
			updated, err := resolve(ctx, resolver, domain, adnlAddr)
			if err != nil {
				continue
			}

			if updated {
				break
			}
		}
		fmt.Println("Domain", domain, "was successfully configured to use for your TON Site!")
		fmt.Println()
		return
	}

	fmt.Println("Domain", domain, "is already configured to use with current ADNL address. Everything is OK!")
}

func resolve(ctx context.Context, client *dns.Client, domain string, adnlAddr []byte) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	domainInfo, err := client.Resolve(ctx, domain)
	if err != nil {
		return false, err
	}

	record, isStorage := domainInfo.GetSiteRecord()
	if isStorage {
		return false, nil
	}

	return bytes.Equal(record, adnlAddr), nil
}
