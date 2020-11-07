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
	dstmac := make([]byte, 8)
	binary.BigEndian.PutUint64(srcmac, fmsg.SrcMac)
	binary.BigEndian.PutUint64(dstmac, fmsg.DstMac)
	srcmac = srcmac[2:8]
	dstmac = dstmac[2:8]
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

	message := fmt.Sprintf("%v.000 %6v %v %v/- %v HEAD %v:%v %v FIRSTUP_PARENT/%v packet_netflow/%v/:%v ",
		fmsg.TimeFlowStart,                  // time
		fmsg.TimeFlowEnd-fmsg.TimeFlowStart, //delay
		net.IP(fmsg.DstAddr).String(),       // dst ip
		protocol,                            // protocol
		fmsg.Bytes,                          // size
		net.IP(fmsg.SrcAddr).String(),       //src ip
		fmsg.SrcPort,                        // src port
		net.HardwareAddr(srcmac).String(),   // srcmac
		net.IP(fmsg.SamplerAddress),         // routerIP
		net.HardwareAddr(dstmac).String(),   //dstmac
		fmsg.DstPort)                        //dstport
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
	var srcIP, srcPort, dstPort string
	valueArray := strings.Fields(line) // разбиваем на поля через пробел
	if len(valueArray) == 0 {          // проверяем длину строки, чтобы убедиться что строка нормально распарсилась\её формат
		return "" // если это не так то возвращаем ничего
	}

	dstIP := valueArray[2]
	dstPortStr := valueArray[9]
	srcIPPort := valueArray[6]
	if len(strings.Split(dstPortStr, "/")) >= 3 {
		dstPort = strings.Split(dstPortStr, "/")[2]
	} else {
		dstPort = "-"
	}
	if len(strings.Split(srcIPPort, ":")) >= 2 {
		srcIP = strings.Split(srcIPPort, ":")[0]
		srcPort = strings.Split(srcIPPort, ":")[1]
	} else {
		srcIP = srcIPPort
	}
	timestamp := valueArray[0]
	delay := valueArray[1]
	protocol := valueArray[3]
	size := valueArray[4]
	typeOfResponse := valueArray[5]
	user := valueArray[7]
	parent := strings.Split(valueArray[8], "/")[1]
	mime := valueArray[9]

	ok := s.CheckForAllSubNet(dstIP)
	ok2 := s.CheckForAllSubNet(srcIP)

	if !ok { // если адрес назначения не принадлежит необходимой подсети
		if *s.ProcessingDirection == "both" { // если трафик считается в оба направления,
			if ok2 && srcIP != parent && dstIP != parent { // если адрес источника не принадлежит внутренним подсетям, то мы меням адреса источника и назначения
				newMac := strings.Split(valueArray[9], "/")[1]
				newSrcPortStr := strings.Split(valueArray[9], "/")[0] + "_inverse/" + valueArray[7] + "/:" + srcPort
				line = fmt.Sprintf("%v %6v %v %v %v %v %v%v %v %v %v ",
					valueArray[0], // time
					valueArray[1], // delay
					srcIP,         // dest ip
					valueArray[3], // TCP_PACKET/-
					valueArray[4], // size
					valueArray[5], // HEAD
					dstIP,         // Src ip
					dstPort,       // src port
					newMac,        // user
					valueArray[8], // FIRSTUP_PARENT/192.168.65.254
					newSrcPortStr) // packet_netflow_inverse/srcmac/srcport

				return line
			}
		}
		return ""

	} else if !ok2 { // если адерс назначения принадлежит внутренним сетям, а адрес источника нет, то отправляем строку как она есть
		if dstIP == parent {
			return ""

		}
		return line

	} else if dstIP == parent { // если адрес srcip и dstip принадлежат внутренним подсетям, то проверяем, не является ли dstip нашим коммутатором. Если является, то меняем местами desip и srcip и пишем в историю
		newMac := strings.Split(mime, "/")[1]
		newSrcPortStr := strings.Split(valueArray[9], "/")[0] + "_inverse/" + user + "/:" + srcPort
		line = fmt.Sprintf("%v %6v %v %v %v %v %v%v %v %v %v ",
			timestamp,      // time
			delay,          // delay
			srcIP,          // dest ip
			protocol,       // TCP_PACKET/-
			size,           // size
			typeOfResponse, // HEAD
			dstIP,          // Src ip
			dstPort,        // src port
			newMac,         // user
			valueArray[8],  // FIRSTUP_PARENT/192.168.65.254
			newSrcPortStr)  // packet_netflow_inverse/srcmac/srcport

	} else if srcIP == parent { // если адрес srcip и dstip принадлежат внутренним подсетям, то проверяем, не является ли scrip нашим коммутатором. Если является, то пишем в историю
		return line

	}

	return ""
}
