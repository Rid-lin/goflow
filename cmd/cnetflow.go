package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"syscall"

	"github.com/cloudflare/goflow/v3/utils"
	"github.com/ilyakaznacheev/cleanenv"
	log "github.com/sirupsen/logrus"
)

type arrayFlags []string

func (i *arrayFlags) String() string {
	return "List of strings"
}

func (i *arrayFlags) Set(value string) error {
	*i = append(*i, value)
	return nil
}

type Config struct {
	SubNets             arrayFlags `yaml:"SubNets" toml:"subnets" env:"SUBNETS"`
	IgnorList           arrayFlags `yaml:"IgnorList" toml:"ignorlist" env:"IGNORLIST"`
	LogLevel            string     `yaml:"LogLevel" toml:"loglevel" env:"LOG_LEVEL"`
	ProcessingDirection string     `yaml:"ProcessingDirection" toml:"direct" env:"DIRECT" env-default:"both"`
	FlowAddr            string     `yaml:"FlowAddr" toml:"flowaddr" env:"FLOW_ADDR"`
	FlowPort            int        `yaml:"FlowPort" toml:"flowport" env:"FLOW_PORT" env-default:"2055"`
	ReuseFlowPort       bool       `yaml:"ReuseFlowPort" toml:"reuseflowport" env:"REUSE_FLOW_PORT"`
	FlowWorkers         int        `yaml:"FlowWorkers" toml:"flowworkers" env:"FLOW_WORKERS" env-default:"1"`
	NameFileToLog       string     `yaml:"FileToLog" toml:"log" env:"FLOW_LOG"`
}

var (
	cfg                Config
	SubNets, IgnorList arrayFlags
	writer             *bufio.Writer
	FileToLog          *os.File
	err                error

	version    = ""
	buildinfos = ""
	AppVersion = "GoFlow NetFlow " + version + " " + buildinfos

	Version = flag.Bool("v", false, "Print version")
)

func init() {
	flag.StringVar(&cfg.FlowAddr, "addr", "", "NetFlow/IPFIX listening address")
	flag.IntVar(&cfg.FlowPort, "port", 2055, "NetFlow/IPFIX listening port")
	flag.BoolVar(&cfg.ReuseFlowPort, "reuse", false, "Enable so_reuseport for NetFlow/IPFIX listening port")
	flag.IntVar(&cfg.FlowWorkers, "workers", 1, "Number of NetFlow workers")
	flag.StringVar(&cfg.LogLevel, "loglevel", "info", "Log level")
	flag.Var(&cfg.SubNets, "subnet", "List of internal subnets")
	flag.Var(&cfg.IgnorList, "ignorlist", "List of ignored words/parameters per string")
	flag.StringVar(&cfg.ProcessingDirection, "direct", "both", "")
	flag.StringVar(&cfg.NameFileToLog, "log", "", "The file where logs will be written in the format of squid logs")
	flag.Parse()
	var config_source string
	if SubNets == nil && IgnorList == nil {
		// err := cleanenv.ReadConfig("goflow.toml", &cfg)
		err := cleanenv.ReadConfig("/etc/goflow/goflow.toml", &cfg)
		if err != nil {
			log.Warningf("No .env file found: %v", err)
		}
		lvl, err2 := log.ParseLevel(cfg.LogLevel)
		if err2 != nil {
			log.Errorf("Error in determining the level of logs (%v). Installed by default = Info", cfg.LogLevel)
			lvl, _ = log.ParseLevel("info")
		}
		log.SetLevel(lvl)
		config_source = "ENV/CFG"
	} else {
		config_source = "CLI"
	}
	log.Debugf("Config read from %s: IgnorList=(%v), SubNets=(%v), FlowAddr=(%v), FlowPort=(%v), ReuseFlowPort=(%v), FlowWorkers=(%v), LogLevel=(%v), ProcessingDirection=(%v)",
		config_source,
		cfg.IgnorList,
		cfg.SubNets,
		cfg.FlowAddr,
		cfg.FlowPort,
		cfg.ReuseFlowPort,
		cfg.FlowWorkers,
		cfg.LogLevel,
		cfg.ProcessingDirection)

}

func main() {

	if cfg.NameFileToLog == "" {
		writer = bufio.NewWriter(os.Stdout)
		log.Debug("Output in os.Stdout")
	} else {
		FileToLog, err = os.OpenFile(cfg.NameFileToLog, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		// FileToLog, err = os.Create(cfg.NameFileToLog)
		if err != nil {
			log.Errorf("Error, the '%v' file could not be created (there are not enough premissions or it is busy with another program): %v", cfg.NameFileToLog, err)
			writer = bufio.NewWriter(os.Stdout)
			FileToLog.Close()
			log.Debug("Output in os.Stdout with error open file")
		} else {
			defer FileToLog.Close()
			writer = bufio.NewWriter(FileToLog)
			log.Debugf("Output in file (%v)(%v)", cfg.NameFileToLog, FileToLog)
		}
	}

	if *Version {
		fmt.Println(AppVersion)
		os.Exit(0)
	}

	var defaultTransport = &utils.DefaultSquidTransport{}
	defaultTransport.Writer = writer
	defaultTransport.IgnorList = cfg.IgnorList
	defaultTransport.SubNets = cfg.SubNets
	defaultTransport.ProcessingDirection = &cfg.ProcessingDirection

	runtime.GOMAXPROCS(runtime.NumCPU())

	log.Info("Starting GoFlow")

	s := &utils.StateNetFlow{
		Transport: defaultTransport,
		Logger:    log.StandardLogger(),
	}

	log.WithFields(log.Fields{
		"Type": "NetFlow"}).
		Infof("Listening on UDP %v:%v", cfg.FlowAddr, cfg.FlowPort)

	exitChan := getExitSignalsChannel()

	go func() {
		<-exitChan
		writer.Flush()
		FileToLog.Close()
		log.Println("Shutting down")
		os.Exit(0)

	}()

	err := s.FlowRoutine(cfg.FlowWorkers, cfg.FlowAddr, cfg.FlowPort, cfg.ReuseFlowPort)
	if err != nil {
		log.Fatalf("Fatal error: could not listen to UDP (%v)", err)
	}
}

func getExitSignalsChannel() chan os.Signal {

	c := make(chan os.Signal, 1)
	signal.Notify(c,
		// https://www.gnu.org/software/libc/manual/html_node/Termination-Signals.html
		syscall.SIGTERM, // "the normal way to politely ask a program to terminate"
		syscall.SIGINT,  // Ctrl+C
		syscall.SIGQUIT, // Ctrl-\
		// syscall.SIGKILL, // "always fatal", "SIGKILL and SIGSTOP may not be caught by a program"
		syscall.SIGHUP, // "terminal is disconnected"
	)
	return c

}
