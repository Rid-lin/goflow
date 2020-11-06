package utils

import (
	"bufio"
	"encoding/binary"
	"flag"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	decoder "github.com/cloudflare/goflow/v3/decoders"
	"github.com/cloudflare/goflow/v3/decoders/netflow"
	flowmessage "github.com/cloudflare/goflow/v3/pb"
	reuseport "github.com/libp2p/go-reuseport"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/log"
)

const defaultFields = "Type,TimeReceived,SequenceNum,SamplingRate,SamplerAddress,TimeFlowStart,TimeFlowEnd,Bytes,Packets,SrcAddr,DstAddr,Etype,Proto,SrcPort,DstPort,InIf,OutIf,SrcMac,DstMac,SrcVlan,DstVlan,VlanId,IngressVrfID,EgressVrfID,IPTos,ForwardingStatus,IPTTL,TCPFlags,IcmpType,IcmpCode,IPv6FlowLabel,FragmentId,FragmentOffset,BiFlowDirection,SrcAS,DstAS,NextHop,NextHopAS,SrcNet,DstNet,HasEncap,SrcAddrEncap,DstAddrEncap,ProtoEncap,EtypeEncap,IPTosEncap,IPTTLEncap,IPv6FlowLabelEncap,FragmentIdEncap,FragmentOffsetEncap,HasMPLS,MPLSCount,MPLS1TTL,MPLS1Label,MPLS2TTL,MPLS2Label,MPLS3TTL,MPLS3Label,MPLSLastTTL,MPLSLastLabel,HasPPP,PPPAddressControl"

var (
	MessageFields = flag.String("message.fields", defaultFields, "The list of fields to include in flow messages")
)

func GetServiceAddresses(srv string) (addrs []string, err error) {
	_, srvs, err := net.LookupSRV("", "", srv)
	if err != nil {
		return nil, fmt.Errorf("Service discovery: %v\n", err)
	}
	for _, srv := range srvs {
		addrs = append(addrs, net.JoinHostPort(srv.Target, strconv.Itoa(int(srv.Port))))
	}
	return addrs, nil
}

type Logger interface {
	Printf(string, ...interface{})
	Errorf(string, ...interface{})
	Warnf(string, ...interface{})
	Warn(...interface{})
	Error(...interface{})
	Debug(...interface{})
	Debugf(string, ...interface{})
	Infof(string, ...interface{})
	Fatalf(string, ...interface{})
}

type BaseMessage struct {
	Src     net.IP
	Port    int
	Payload []byte

	SetTime  bool
	RecvTime time.Time
}

type Transport interface {
	Publish([]*flowmessage.FlowMessage)
	CheckForAllSubNet(ip string) bool
	RemoveIgnoringLine(line string) string
}

type DefaultSquidTransport struct {
	Writer              *bufio.Writer
	SubNets             []string
	IgnorList           []string
	ProcessingDirection *string
}

func (s *DefaultSquidTransport) Publish(msgs []*flowmessage.FlowMessage) {
	for _, msg := range msgs {
		message := FlowMessageToSquid(msg)
		message = s.RemoveIgnoringLine(message)
		if message == "" {
			continue
		}
		message = s.LogFileFiltering(message)
		if message == "" {
			continue
		}
		fmt.Fprintf(s.Writer, "%v\n", message)
	}
}

type DefaultErrorCallback struct {
	Logger Logger
}

func (cb *DefaultErrorCallback) Callback(name string, id int, start, end time.Time, err error) {
	if _, ok := err.(*netflow.ErrorTemplateNotFound); ok {
		return
	}
	if cb.Logger != nil {
		cb.Logger.Errorf("Error from: %v (%v) duration: %v. %v", name, id, end.Sub(start), err)
	}
}

func FlowMessageToSquid(fmsg *flowmessage.FlowMessage) string {
	srcmac := make([]byte, 8)
	binary.BigEndian.PutUint64(srcmac, fmsg.SrcMac)
	srcmac = srcmac[2:8]
	var protocol string

	switch fmt.Sprintf("%v", fmsg.Proto) {
	case "6":
		protocol = "TCP_PACKET"
	case "17":
		protocol = "UDP_PACKET"
	case "1":
		protocol = "ICMP_PACKET"

	default:
		protocol = "OTHER_PACKET"
	}

	message := fmt.Sprintf("%v.000 %6v %v %v/- %v HEAD %v:%v %v FIRSTUP_PARENT/%v packet_netflow/:%v ", fmsg.TimeFlowStart, fmsg.TimeFlowEnd-fmsg.TimeFlowStart, net.IP(fmsg.DstAddr).String(), protocol, fmsg.Bytes, net.IP(fmsg.SrcAddr).String(), fmsg.SrcPort, net.HardwareAddr(srcmac).String(), net.IP(fmsg.SamplerAddress), fmsg.DstPort)
	return message
}

func UDPRoutine(name string, decodeFunc decoder.DecoderFunc, workers int, addr string, port int, sockReuse bool, logger Logger) error {
	ecb := DefaultErrorCallback{
		Logger: logger,
	}

	decoderParams := decoder.DecoderParams{
		DecoderFunc:   decodeFunc,
		DoneCallback:  DefaultAccountCallback,
		ErrorCallback: ecb.Callback,
	}

	processor := decoder.CreateProcessor(workers, decoderParams, name)
	processor.Start()

	addrUDP := net.UDPAddr{
		IP:   net.ParseIP(addr),
		Port: port,
	}

	var udpconn *net.UDPConn
	var err error

	if sockReuse {
		pconn, err := reuseport.ListenPacket("udp", addrUDP.String())
		if err != nil {
			return err
		}
		defer pconn.Close()
		var ok bool
		udpconn, ok = pconn.(*net.UDPConn)
		if !ok {
			return err
		}
	} else {
		udpconn, err = net.ListenUDP("udp", &addrUDP)
		if err != nil {
			return err
		}
		defer udpconn.Close()
	}

	payload := make([]byte, 9000)

	localIP := addrUDP.IP.String()
	if addrUDP.IP == nil {
		localIP = ""
	}

	for {
		size, pktAddr, _ := udpconn.ReadFromUDP(payload)
		payloadCut := make([]byte, size)
		copy(payloadCut, payload[0:size])

		baseMessage := BaseMessage{
			Src:     pktAddr.IP,
			Port:    pktAddr.Port,
			Payload: payloadCut,
		}
		processor.ProcessMessage(baseMessage)

		MetricTrafficBytes.With(
			prometheus.Labels{
				"remote_ip":   pktAddr.IP.String(),
				"remote_port": strconv.Itoa(pktAddr.Port),
				"local_ip":    localIP,
				"local_port":  strconv.Itoa(addrUDP.Port),
				"type":        name,
			}).
			Add(float64(size))
		MetricTrafficPackets.With(
			prometheus.Labels{
				"remote_ip":   pktAddr.IP.String(),
				"remote_port": strconv.Itoa(pktAddr.Port),
				"local_ip":    localIP,
				"local_port":  strconv.Itoa(addrUDP.Port),
				"type":        name,
			}).
			Inc()
		MetricPacketSizeSum.With(
			prometheus.Labels{
				"remote_ip":   pktAddr.IP.String(),
				"remote_port": strconv.Itoa(pktAddr.Port),
				"local_ip":    localIP,
				"local_port":  strconv.Itoa(addrUDP.Port),
				"type":        name,
			}).
			Observe(float64(size))
	}
}

func (s *DefaultSquidTransport) CheckForAllSubNet(ip string) bool {
	for _, subNet := range s.SubNets {
		ok, err := checkIP(subNet, ip)
		if err != nil { // если ошибка, то следующая строка
			log.Error("Error while determining the IP subnet address:", err)
			return false

		}
		if ok {
			return true
		}
	}

	return false
}

// Получает на вход строку в виде лога Squid по-умолчанию
// Фильтрует от лишних записей по вхождению строк из списка в конфиге
func (s *DefaultSquidTransport) RemoveIgnoringLine(line string) string {
	for _, ignorItem := range s.IgnorList { //проходим по списку исключения,
		if strings.Contains(line, ignorItem) { //если линия содержит хотя бы один объект из списка,
			return "" // то мы её игнорируем и возвращаем ничего

		}
	}
	return line

}

func checkIP(subnet, ip string) (bool, error) {
	_, netA, err := net.ParseCIDR(subnet)
	if err != nil {
		return false, err
	}
	// convert string to IP
	ipv4addr := net.ParseIP(ip)

	return netA.Contains(ipv4addr), nil
}

func (s *DefaultSquidTransport) LogFileFiltering(line string) string {
	var destIP, destPort, srcPort string
	valueArray := strings.Fields(line) // разбиваем на поля через пробел
	if len(valueArray) == 0 {          // проверяем длину строки, чтобы убедиться что строка нормально распарсилась\её формат
		return "" // если это не так то возвращаем ничего
	}

	srcIP := valueArray[2]
	srcPortStr := valueArray[9]
	destIPPort := valueArray[6]
	if len(strings.Split(srcPortStr, "/")) >= 2 {
		srcPort = strings.Split(srcPortStr, "/")[1]
	} else {
		srcPort = "-"
	}
	if len(strings.Split(destIPPort, ":")) >= 2 {
		destIP = strings.Split(destIPPort, ":")[0]
		destPort = strings.Split(destIPPort, ":")[1]
	} else {
		destIP = destIPPort
	}
	ok := s.CheckForAllSubNet(srcIP)
	ok2 := s.CheckForAllSubNet(destIP)

	if !ok { // если адрес не принадлежит необходимой подсети
		if *s.ProcessingDirection == "both" { // если трафик считается в оба направления,
			if ok2 { // если адрес назначения не входит указанные подсети
				newSrcPortStr := strings.Split(valueArray[9], "/")[0] + "_inverse/:" + destPort
				line = fmt.Sprintf("%v %6v %v %v %v %v %v%v %v %v %v ", valueArray[0], valueArray[1], destIP, valueArray[3], valueArray[4], valueArray[5], srcIP, srcPort, valueArray[7], valueArray[8], newSrcPortStr)

				return line
			}
		}
		return ""

	} else if !ok2 {
		return line

	}

	return ""
}
