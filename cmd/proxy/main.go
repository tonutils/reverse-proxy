package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/mdp/qrterminal/v3"
	"github.com/sigurn/crc16"
	"github.com/xssnick/tonutils-go/adnl/dht"
	rldphttp "github.com/xssnick/tonutils-go/adnl/rldp/http"
	"github.com/xssnick/tonutils-go/liteclient"
	"github.com/xssnick/tonutils-go/tlb"
	"github.com/xssnick/tonutils-go/ton"
	"github.com/xssnick/tonutils-go/ton/dns"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"time"
)

type Config struct {
	ProxyPass  string `json:"proxy_pass"`
	ForwardTo  string `json:"forward_to"`
	PrivateKey []byte `json:"private_key"`
	IP         string `json:"address"`
	Port       uint16 `json:"port"`
}

var FlagDomain = flag.String("domain", "", "domain to configure")

type Handler struct {
	h http.Handler
}

func (h Handler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	hdr := http.Header{}
	for k := range request.Header {
		// exception for ton.run, make headers canonical
		hdr.Set(k, request.Header.Get(k))
	}
	request.Header = hdr

	log.Println("request:", request.Method, request.Host, request.RequestURI)
	h.h.ServeHTTP(writer, request)
}

func main() {
	flag.Parse()

	cfg, err := loadConfig()
	if err != nil {
		panic("failed to load config: " + err.Error())
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	netCfg, err := liteclient.GetConfigFromUrl(ctx, "https://ton-blockchain.github.io/global.config.json")
	if err != nil {
		panic("failed to load network config: " + err.Error())
	}

	client := liteclient.NewConnectionPool()
	// connect to testnet lite server
	err = client.AddConnectionsFromConfig(ctx, netCfg)
	if err != nil {
		panic(err)
	}

	dhtClient, err := dht.NewClientFromConfig(ctx, netCfg)
	if err != nil {
		panic(err)
	}

	u, err := url.Parse(cfg.ProxyPass)
	if err != nil {
		panic(err)
	}

	proxy := httputil.NewSingleHostReverseProxy(u)
	s := rldphttp.NewServer(ed25519.NewKeyFromSeed(cfg.PrivateKey), dhtClient, Handler{proxy})

	addr, err := rldphttp.SerializeADNLAddress(s.Address())
	if err != nil {
		panic(err)
	}
	log.Println("Server's ADNL address is", addr+".adnl")

	if *FlagDomain != "" {
		setupDomain(client, *FlagDomain, s.Address())
	}

	log.Println("Starting server on", addr+".adnl")
	if err = s.ListenAndServe(fmt.Sprintf("%s:%d", cfg.IP, cfg.Port)); err != nil {
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

		cfg.IP, err = getPublicIP()
		if err != nil {
			return nil, err
		}

		// generate consistent port
		cfg.Port = 9000 + (crc16.Checksum([]byte(cfg.IP), crc16.MakeTable(crc16.CRC16_XMODEM)) % 5000)

		cfg.ProxyPass = "http://127.0.0.1:80/"

		data, err = json.MarshalIndent(cfg, "", "\t")
		if err != nil {
			return nil, err
		}

		err = os.WriteFile(file, data, 555)
		if err != nil {
			return nil, err
		}

		return &cfg, nil
	}

	err = json.Unmarshal(data, &cfg)
	if err != nil {
		return nil, err
	}

	return &cfg, nil
}

func setupDomain(client *liteclient.ConnectionPool, domain string, adnlAddr []byte) {
	ctx := client.StickyContext(context.Background())
	// initialize ton api lite connection wrapper
	api := ton.NewAPIClient(client)

	// get root dns address from network config
	root, err := dns.RootContractAddr(api)
	if err != nil {
		panic(err)
	}

	resolver := dns.NewDNSClient(api, root)
	domainInfo, err := resolver.Resolve(ctx, domain)
	if err != nil {
		log.Println("Failed to configure domain", domain, ":", err)
		return
	}

	if !bytes.Equal(domainInfo.GetSiteRecord(), adnlAddr) {
		data := domainInfo.BuildSetSiteRecordPayload(adnlAddr).ToBOCWithFlags(false)
		args := "?bin=" + base64.URLEncoding.EncodeToString(data) + "&amount=" + tlb.MustFromTON("0.05").NanoTON().String()

		qrterminal.GenerateHalfBlock("ton://transfer/"+domainInfo.GetNFTAddress().String()+args, qrterminal.L, os.Stdout)
		fmt.Println("Execute this transaction from the domain owner's wallet to setup site records.")
		fmt.Println("When you've done, configuration will automatically proceed in ~10 seconds.")
		for {
			time.Sleep(5 * time.Second)
			updated, err := resolve(resolver, domain, adnlAddr)
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

func resolve(client *dns.Client, domain string, adnlAddr []byte) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	domainInfo, err := client.Resolve(ctx, domain)
	if err != nil {
		return false, err
	}

	return bytes.Equal(domainInfo.GetSiteRecord(), adnlAddr), nil
}
