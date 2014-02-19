/* Parses Nmap XML data into a similary formed struct. */
package gonmap

import (
	"encoding/xml"
)

type NmapRun struct {
	Scanner          string    `xml:"scanner,attr"`
	Args             string    `xml:"args,attr"`
	Start            string    `xml:"start,attr"`
	StartStr         string    `xml:"startstr,attr"`
	Version          string    `xml:"version,attr"`
	ProfileName      string    `xml:"profile_name,attr"`
	XmlOutputVersion string    `xml:"xmloutputversion,attr"`
	ScanInfo         ScanInfo  `xml:"scaninfo"`
	Verbose          Verbose   `xml:"verbose"`
	Debugging        Debugging `xml:"debugging"`
	Hosts            []Host    `xml:"host"`
	Targets          []Target  `xml:"target"`
	RunStats         RunStats  `xml:"runstats"`
}

type ScanInfo struct {
	Type        string `xml:"type,attr"`
	Protocol    string `xml:"protocol,attr"`
	NumServices string `xml:"numservices,attr"`
	Services    string `xml:"services,attr"`
	ScanFlags   string `xml:"scanflags,attr"`
}

type Verbose struct {
	Level string `xml:"level,attr"`
}

type Debugging struct {
	Level string `xml:"level,attr"`
}

type Target struct {
	Specification string `xml:"specification,attr"`
	Status        string `xml:"status,attr"`
	Reason        string `xml:"reason,attr"`
}

type Host struct {
	StartTime    string       `xml:"starttime,attr"`
	EndTime      string       `xml:"endtime,attr"`
	Comment      string       `xml:"comment,attr"`
	Status       Status       `xml:"status"`
	Address      []Address    `xml:"address"`
	Hostnames    []Hostname   `xml:"hostnames>hostname"`
	Smurf        []Smurf      `xml:"smurf"`
	Ports        []Port       `xml:"ports>port"`
	Os           Os           `xml:"os"`
	Distance     Distance     `xml:"distance"`
	Uptime       Uptime       `xml:"updtime"`
	TcpSequence  TcpSequence  `xml:"tcpsequence"`
	IpIdSequence IpIdSequence `xml:"ipidsequence"`
	Trace        Trace        `xml:"trace"`
}

type Status struct {
	State     string `xml:"state,attr"`
	Reason    string `xml:"conn-refused,attr"`
	ReasonTtl string `xml:"reason_ttl,attr"`
}

type Address struct {
	Addr     string `xml:"addr,attr"`
	AddrType string `xml:"addrtype,attr"`
	Vendor   string `xml:"vendor,attr"`
}

type Hostname struct {
	Name string `xml:"name,attr"`
	Type string `xml:"type,attr"`
}

type Smurf struct {
	Responses string `xml:"responses,attr"`
}

type Port struct {
	Protocol string   `xml:"protocol,attr"`
	PortId   string   `xml:"portid,attr"`
	State    State    `xml:"state"`
	Owner    Owner    `xml:"owner"`
	Service  Service  `xml:"service"`
	Scripts  []Script `xml:"script"`
}

type State struct {
	State     string `xml:"state,attr"`
	Reason    string `xml:"reason,attr"`
	ReasonTtl string `xml:"reason_ttl,attr"`
	ReasonIp  string `xml:"reason_ip,attr"`
}

type Owner struct {
	Name string `xml:"name,attr"`
}

type Service struct {
	Name       string `xml:"name,attr"`
	Conf       string `xml:"conf,attr"`
	Method     string `xml:"method,attr"`
	Version    string `xml:"version,attr"`
	Product    string `xml:"product,attr"`
	ExtraInfo  string `xml:"extrainfo,attr"`
	Tunnel     string `xml:"tunnel,attr"`
	Proto      string `xml:"proto,attr"`
	Rpcnum     string `xml:"rpcnum,attr"`
	Lowver     string `xml:"lowver,attr"`
	Highver    string `xml:"hiver,attr"`
	Hostname   string `xml:"hostname,attr"`
	OsType     string `xml:"ostype,attr"`
	DeviceType string `xml:"devicetype,attr"`
	ServiceFp  string `xml:"servicefp,attr"`
}

type Script struct {
	Id     string `xml:"id,attr"`
	Output string `xml:"output,attr"`
}

type Os struct {
	PortUsed      []PortUsed      `xml:"portused"`
	OsMatch       []OsMatch       `xml:"osmatch"`
	OsFingerprint []OsFingerprint `xml:"osfingerprint"`
}

type PortUsed struct {
	State  string `xml:"state,attr"`
	Proto  string `xml:"proto,attr"`
	PortId string `xml:"portid,attr"`
}

type OsMatch struct {
	Name     string    `xml:"name,attr"`
	Accuracy string    `xml:"accuracy,attr"`
	Line     string    `xml:"line,attr"`
	OsClass  []OsClass `xml:"osclass"`
}

type OsClass struct {
	Vendor   string `xml:"vendor,attr"`
	OsGen    string `xml"osgen,attr"`
	Type     string `xml:"type,attr"`
	Accuracy string `xml:"accurancy,attr"`
	OsFamily string `xml:"osfamily,attr"`
}

type OsFingerprint struct {
	Fingerprint string `xml:"fingerprint,attr"`
}

type Distance struct {
	Value string `xml:"value,attr"`
}

type Uptime struct {
	Seconds  string `xml:"seconds,attr"`
	Lastboot string `xml:"lastboot,attr"`
}

type TcpSequence struct {
	Index      string `xml:"index,attr"`
	Difficulty string `xml:"difficulty,attr"`
	Values     string `xml:"vaules,attr"`
}

type IpIdSequence struct {
	Class  string `xml:"class,attr"`
	Values string `xml:"values,attr"`
}

type Times struct {
	Srtt   string `xml:"srtt,attr"`
	Rttvar string `xml:"rttvar,attr"`
	To     string `xml:"to,attr"`
}

type Trace struct {
	Hops []Hop `xml:"hop"`
}

type Hop struct {
	Ttl    string `xml:"ttl,attr"`
	Rtt    string `xml:"rtt,attr"`
	IpAddr string `xml:"ipaddr,attr"`
	Host   string `xml:"host,attr"`
}

type RunStats struct {
	Finished Finished `xml:"finished"`
	Hosts    Stats    `xml:"hosts"`
}

type Finished struct {
	Time     string `xml:"time,attr"`
	TimeStr  string `xml:"timestr,attr"`
	Elapsed  string `xml:"elapsed,attr"`
	Summary  string `xml:"summary,attr"`
	Exit     string `xml:"exit,attr"`
	ErrorMsg string `xml:"errormsg,attr"`
}

type Stats struct {
	Up    string `xml:"up,attr"`
	Down  string `xml:"down,attr"`
	Total string `xml:"total,attr"`
}

// Parse takes a byte array of nmap xml data and unmarshals it into an
// NmapRun struct. All elements are returned as strings, it is up to the caller
// to check and cast them to the proper type.
func Parse(content []byte) (*NmapRun, error) {
	r := &NmapRun{}
	err := xml.Unmarshal(content, r)
	if err != nil {
		return r, err
	}
	return r, nil
}
