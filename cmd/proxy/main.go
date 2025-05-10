package main

import "C"
import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/mdp/qrterminal/v3"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/sigurn/crc16"
	tunnelConfig "github.com/ton-blockchain/adnl-tunnel/config"
	"github.com/ton-blockchain/adnl-tunnel/tunnel"
	"github.com/ton-utils/reverse-proxy/config"
	"github.com/ton-utils/reverse-proxy/rldphttp"
	"github.com/xssnick/tonutils-go/adnl"
	"github.com/xssnick/tonutils-go/adnl/address"
	"github.com/xssnick/tonutils-go/adnl/dht"
	"github.com/xssnick/tonutils-go/adnl/rldp"
	"github.com/xssnick/tonutils-go/liteclient"
	"github.com/xssnick/tonutils-go/tlb"
	"github.com/xssnick/tonutils-go/ton"
	"github.com/xssnick/tonutils-go/ton/dns"
	"io"
	regularLog "log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

type Config struct {
	ProxyPass                    string                    `json:"proxy_pass"`
	PrivateKey                   []byte                    `json:"private_key"`
	ExternalIP                   string                    `json:"external_ip"`
	ListenIP                     string                    `json:"listen_ip"`
	NetworkConfigURL             string                    `json:"network_config_url"`
	CustomTunnelNetworkConfigURL string                    `json:"custom_tunnel_network_config_url"`
	Port                         uint16                    `json:"port"`
	TunnelConfig                 tunnelConfig.ClientConfig `json:"tunnel_config"`
	Version                      int                       `json:"version"`
}

var FlagDomain = flag.String("domain", "", "domain to configure")
var FlagDebug = flag.Bool("debug", false, "more logs")
var FlagAllowInsecureHttps = flag.Bool("allow-insecure-https", false, "allow insecure https")
var FlagTxURL = flag.Bool("tx-url", false, "show set domain record url instead of qr")
var EnableTunnel = flag.Bool("enable-tunnel", false, "enable tunnel mode, to host site with no public ip (should be configured first)")

var GitCommit = "dev"

func envOrVal(env string, arg any) any {
	var res = arg

	val, exists := os.LookupEnv(env)
	if exists && val != "" {
		switch arg.(type) {
		case []byte:
			v, err := base64.StdEncoding.DecodeString(val)
			if err != nil {
				panic(err.Error())
			}
			return v
		case uint16:
			v, err := strconv.ParseUint(val, 10, 16)
			if err != nil {
				panic(err.Error())
			}
			return uint16(v)
		case string:
			return val
		case bool:
			ok := strings.ToLower(val) != "0" && strings.ToLower(val) != "false"
			return ok
		}
	}

	return res
}

type Handler struct {
	h http.Handler
}

func (h Handler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if *FlagDebug {
		reqDump, err := httputil.DumpRequestOut(request, true)
		if err != nil {
			return
		}
		log.Debug().
			Str("request_dump", string(reqDump)).
			Msg("Dumping HTTP request")
	}

	hdr := http.Header{}
	for k := range request.Header {
		// make headers canonical
		for _, s := range request.Header.Values(k) {
			hdr.Add(k, s)
		}
	}
	request.Header = hdr

	log.Debug().
		Str("method", request.Method).
		Str("host", request.Host).
		Str("uri", request.RequestURI).
		Msg("Received HTTP request")

	writer.Header().Set("Ton-Reverse-Proxy", "Tonutils Reverse Proxy "+GitCommit)
	h.h.ServeHTTP(writer, request)
}

func main() {
	flag.Parse()

	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stdout}).Level(zerolog.InfoLevel)
	if *FlagDebug {
		log.Logger = log.Logger.Level(zerolog.DebugLevel)
	}

	log.Info().Str("version", GitCommit).Msg("Starting Tonutils Reverse Proxy")

	cfg, err := loadConfig()
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to load config")
	}

	netCfg, err := liteclient.GetConfigFromUrl(context.Background(), cfg.NetworkConfigURL)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to download TON config, using static cache")
		netCfg = &liteclient.GlobalConfig{}
		if err = json.NewDecoder(bytes.NewBufferString(config.FallbackNetworkConfig)).Decode(netCfg); err != nil {
			log.Fatal().Err(err).Msg("Failed to parse fallback TON config")
		}
	}

	client := liteclient.NewConnectionPool()

	closerCtx, stop := context.WithCancel(context.Background())
	defer stop()

	ctx, cancel := context.WithTimeout(closerCtx, 30*time.Second)
	defer cancel()

	err = client.AddConnectionsFromConfig(ctx, netCfg)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to add connections from config")
	}

	tunnelCtx, tunnelStop := context.WithCancel(context.Background())

	port := cfg.Port
	ip := net.ParseIP(cfg.ExternalIP)

	var netMgr adnl.NetManager
	var gate *adnl.Gateway
	if *EnableTunnel {
		tunNetCfg := netCfg
		if cfg.CustomTunnelNetworkConfigURL != "" {
			log.Info().Str("url", cfg.CustomTunnelNetworkConfigURL).Msg("Using custom tunnel network config")
			tunNetCfg, err = liteclient.GetConfigFromUrl(context.Background(), cfg.CustomTunnelNetworkConfigURL)
			if err != nil {
				log.Fatal().Err(err).Msg("Failed to download custom tunnel network config")
				return
			}
		}

		log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stdout}).Level(zerolog.InfoLevel)
		if *FlagDebug {
			log.Logger = log.Logger.Level(zerolog.DebugLevel)
		}

		if cfg.TunnelConfig.NodesPoolConfigPath == "" {
			log.Fatal().Msg("Nodes pool config path is empty")
			return
		}

		data, err := os.ReadFile(cfg.TunnelConfig.NodesPoolConfigPath)
		if err != nil {
			log.Fatal().Err(err).Msg("Failed to load tunnel nodes pool config")
			return
		}

		var tunSharedCfg tunnelConfig.SharedConfig
		if err = json.Unmarshal(data, &tunSharedCfg); err != nil {
			log.Fatal().Err(err).Msg("Failed to parse tunnel shared config (nodes pool)")
			return
		}

		events := make(chan any, 1)
		go tunnel.RunTunnel(closerCtx, &cfg.TunnelConfig, &tunSharedCfg, tunNetCfg, log.Logger, events)

		initUpd := make(chan tunnel.UpdatedEvent, 1)
		once := sync.Once{}
		go func() {
			for event := range events {
				switch e := event.(type) {
				case tunnel.StoppedEvent:
					tunnelStop()
					return
				case tunnel.UpdatedEvent:
					log.Info().Msg("Tunnel updated")

					e.Tunnel.SetOutAddressChangedHandler(func(addr *net.UDPAddr) {
						log.Info().Str("addr", addr.IP.String()).Int("port", addr.Port).Msg("Out address updated")

						gate.SetAddressList([]*address.UDP{
							{
								IP:   addr.IP,
								Port: int32(addr.Port),
							},
						})
					})

					once.Do(func() {
						initUpd <- e
					})
				case tunnel.ConfigurationErrorEvent:
					log.Err(e.Err).Msg("Tunnel configuration error, will retry...")
				case error:
					log.Fatal().Err(e).Msg("Tunnel failed")
				}
			}
		}()

		upd := <-initUpd
		netMgr = adnl.NewMultiNetReader(upd.Tunnel)
		gate = adnl.NewGatewayWithNetManager(ed25519.NewKeyFromSeed(cfg.PrivateKey), netMgr)

		log.Info().Str("out_ip", upd.ExtIP.String()).Msg("Using tunnel")
		ip = upd.ExtIP
		port = upd.ExtPort
	} else {
		addr := cfg.ListenIP + ":" + strconv.Itoa(int(cfg.Port))
		dl, err := adnl.DefaultListener(addr)
		if err != nil {
			log.Fatal().Err(err).Str("addr", addr).Msg("Failed to create listener")
			return
		}
		netMgr = adnl.NewMultiNetReader(dl)
		gate = adnl.NewGatewayWithNetManager(ed25519.NewKeyFromSeed(cfg.PrivateKey), netMgr)
	}

	gate.SetAddressList([]*address.UDP{
		{
			IP:   ip.To4(),
			Port: int32(port),
		},
	})

	_, dhtAdnlKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to generate key for DHT")
	}

	dhtGateway := adnl.NewGatewayWithNetManager(dhtAdnlKey, netMgr)
	err = dhtGateway.StartClient()
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to start ADNL gateway client")
	}

	dhtClient, err := dht.NewClientFromConfig(dhtGateway, netCfg)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to create DHT client from config")
	}

	u, err := url.Parse(cfg.ProxyPass)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to parse proxy pass URL")
	}

	if *FlagDebug == false {
		adnl.Logger = func(v ...any) {}
		rldphttp.Logger = func(v ...any) {}
	} else {
		rldp.Logger = regularLog.Println
		rldphttp.Logger = regularLog.Println
		// adnl.Logger = regularLog.Println
	}

	proxy := httputil.NewSingleHostReverseProxy(u)
	if *FlagAllowInsecureHttps {
		proxy.Transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	}
	s := rldphttp.NewServer(ed25519.NewKeyFromSeed(cfg.PrivateKey), gate, dhtClient, Handler{proxy})

	addr, err := rldphttp.SerializeADNLAddress(s.Address())
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to serialize ADNL address")
	}
	log.Info().Str("ADNL_address", addr).Str("hex_address", hex.EncodeToString(s.Address())).Msg("Server's ADNL address")

	if *FlagDomain != "" {
		setupDomain(client, *FlagDomain, s.Address())
	}

	go func() {
		log.Info().Str("address", addr+".adnl").Msg("Starting server")
		if err = s.ListenAndServe(fmt.Sprintf("%s:%d", cfg.ListenIP, cfg.Port)); err != nil {
			log.Fatal().Err(err).Msg("Failed to listen and serve")
		}
	}()

	stopChan := make(chan os.Signal, 1)
	signal.Notify(stopChan, os.Interrupt, syscall.SIGTERM)

	<-stopChan

	stop()

	log.Info().Msg("Received stop signal, shutting down...")
	if *EnableTunnel {
		log.Info().Msg("Stopping tunnel...")
		<-tunnelCtx.Done()
	}

	log.Info().Msg("Server stopped")
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

	save := false
	file := "./config.json"
	data, err := os.ReadFile(file)
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, err
		}

		var srvKey ed25519.PrivateKey
		_, srvKey, err = ed25519.GenerateKey(nil)
		if err != nil {
			return nil, err
		}
		cfg.Version = 1
		cfg.PrivateKey = srvKey.Seed()
		cfg.NetworkConfigURL = "https://ton.org/global.config.json"

		cfg.ExternalIP, err = getPublicIP()
		if err != nil {
			return nil, fmt.Errorf("failed to get public ip: %w", err)
		}
		cfg.ListenIP = "0.0.0.0"

		// generate consistent port
		cfg.Port = 9000 + (crc16.Checksum([]byte(cfg.ExternalIP), crc16.MakeTable(crc16.CRC16_XMODEM)) % 5000)

		cfg.ProxyPass = "http://127.0.0.1:80/"
		tc, err := tunnelConfig.GenerateClientConfig()
		if err != nil {
			return nil, fmt.Errorf("failed to generate tunnel config: %w", err)
		}

		cfg.TunnelConfig = *tc
		save = true
	} else {
		err = json.Unmarshal(data, &cfg)
		if err != nil {
			return nil, err
		}
	}

	if cfg.Version < 1 {
		tc, err := tunnelConfig.GenerateClientConfig()
		if err != nil {
			return nil, fmt.Errorf("failed to generate tunnel config: %w", err)
		}
		cfg.Version = 1
		cfg.TunnelConfig = *tc

		if cfg.NetworkConfigURL == "" {
			cfg.NetworkConfigURL = "https://ton-blockchain.github.io/global.config.json"
		}
		save = true
	}

	if save {
		data, err = json.MarshalIndent(cfg, "", "\t")
		if err != nil {
			return nil, err
		}

		err = os.WriteFile(file, data, 0644) // rw-r--r--
		if err != nil {
			return nil, err
		}
	}

	cfg.ExternalIP = envOrVal("EXTERNAL_IP", cfg.ExternalIP).(string)
	cfg.ListenIP = envOrVal("LISTEN_IP", cfg.ListenIP).(string)
	cfg.Port = envOrVal("LISTEN_PORT", cfg.Port).(uint16)
	cfg.ProxyPass = envOrVal("PROXY_PASS", cfg.ProxyPass).(string)
	cfg.PrivateKey = envOrVal("PRIVATE_KEY", cfg.PrivateKey).([]byte)
	cfg.NetworkConfigURL = envOrVal("NETWORK_CONFIG_URL", cfg.NetworkConfigURL).(string)

	return &cfg, nil
}

func setupDomain(client *liteclient.ConnectionPool, domain string, adnlAddr []byte) {
	ctx := client.StickyContext(context.Background())
	// initialize ton api lite connection wrapper
	api := ton.NewAPIClient(client)

	// get root dns address from network config
	root, err := dns.GetRootContractAddr(ctx, api)
	if err != nil {
		log.Error().Err(err).Msg("Failed to resolve root dns contract")
		return
	}

	resolver := dns.NewDNSClient(api, root)
	domainInfo, err := resolver.Resolve(ctx, domain)
	if err != nil {
		log.Error().Err(err).Str("domain", domain).Msg("Failed to configure domain")
		return
	}

	record, isStorage := domainInfo.GetSiteRecord()
	if isStorage || !bytes.Equal(record, adnlAddr) {
		data := domainInfo.BuildSetSiteRecordPayload(adnlAddr, false).ToBOCWithFlags(false)
		args := "?bin=" + base64.URLEncoding.EncodeToString(data) + "&amount=" + tlb.MustFromTON("0.02").Nano().String()

		nftData, err := domainInfo.GetNFTData(ctx)
		if err != nil {
			log.Error().Err(err).Str("domain", domain).Msg("Failed to get domain data")
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
				log.Warn().Err(err).Str("domain", domain).Msg("Retrying domain resolution")
				continue
			}

			if updated {
				break
			}
		}
		log.Info().Str("domain", domain).Msg("Domain successfully configured to use for your TON Site")
		return
	}

	log.Info().Str("domain", domain).Msg("Domain is already configured to use with current ADNL address. Everything is OK!")
}

func resolve(ctx context.Context, client *dns.Client, domain string, adnlAddr []byte) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	domainInfo, err := client.Resolve(ctx, domain)
	if err != nil {
		log.Error().Err(err).Str("domain", domain).Msg("Failed to resolve domain")
		return false, err
	}

	record, isStorage := domainInfo.GetSiteRecord()
	if isStorage {
		return false, nil
	}

	return bytes.Equal(record, adnlAddr), nil
}
