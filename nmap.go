/*Package nmap parses Nmap XML data into a similary formed struct.*/
package nmap

import (
	"encoding/xml"
)

// NmapRun is contains all the data for a single nmap scan.
type NmapRun struct {
	Scanner          string    `xml:"scanner,attr"`
	Args             string    `xml:"args,attr"`
	Start            string    `xml:"start,attr"`
	StartStr         string    `xml:"startstr,attr"`
	Version          string    `xml:"version,attr"`
	ProfileName      string    `xml:"profile_name,attr"`
	XMLOutputVersion string    `xml:"xmloutputversion,attr"`
	ScanInfo         ScanInfo  `xml:"scaninfo"`
	Verbose          Verbose   `xml:"verbose"`
	Debugging        Debugging `xml:"debugging"`
	Hosts            []Host    `xml:"host"`
	Targets          []Target  `xml:"target"`
	RunStats         RunStats  `xml:"runstats"`
}

// ScanInfo contains informational regarding how the scan
// was run.
type ScanInfo struct {
	Type        string `xml:"type,attr"`
	Protocol    string `xml:"protocol,attr"`
	NumServices string `xml:"numservices,attr"`
	Services    string `xml:"services,attr"`
	ScanFlags   string `xml:"scanflags,attr"`
}

// Verbose contains the verbosity level for the Nmap scan.
type Verbose struct {
	Level string `xml:"level,attr"`
}

// Debugging contains the debugging level for the Nmap scan.
type Debugging struct {
	Level string `xml:"level,attr"`
}

// Target is found in the Nmap xml spec. I have no idea what it
// actually is.
type Target struct {
	Specification string `xml:"specification,attr"`
	Status        string `xml:"status,attr"`
	Reason        string `xml:"reason,attr"`
}

// Host contains all information about a single host.
type Host struct {
	StartTime    string       `xml:"starttime,attr"`
	EndTime      string       `xml:"endtime,attr"`
	Comment      string       `xml:"comment,attr"`
	Status       Status       `xml:"status"`
	Addresses    []Address    `xml:"address"`
	Hostnames    []Hostname   `xml:"hostnames>hostname"`
	Smurf        []Smurf      `xml:"smurf"`
	Ports        []Port       `xml:"ports>port"`
	Os           Os           `xml:"os"`
	Distance     Distance     `xml:"distance"`
	Uptime       Uptime       `xml:"updtime"`
	TcpSequence  TcpSequence  `xml:"tcpsequence"`
	IPIdSequence IPIdSequence `xml:"ipidsequence"`
	Trace        Trace        `xml:"trace"`
}

// Status is the host's status. Up, down, etc.
type Status struct {
	State     string `xml:"state,attr"`
	Reason    string `xml:"reason,attr"`
	ReasonTTL string `xml:"reason_ttl,attr"`
}

// Address contains a IPv4 or IPv6 address for a Host.
type Address struct {
	Addr     string `xml:"addr,attr"`
	AddrType string `xml:"addrtype,attr"`
	Vendor   string `xml:"vendor,attr"`
}

// Hostname is a single name for a Host.
type Hostname struct {
	Name string `xml:"name,attr"`
	Type string `xml:"type,attr"`
}

// Smurf contains repsonses from a smurf attack. I think.
// Smurf attacks, really?
type Smurf struct {
	Responses string `xml:"responses,attr"`
}

// Port contains all the information about a scanned port.
type Port struct {
	Protocol string   `xml:"protocol,attr"`
	PortId   int      `xml:"portid,attr"`
	State    State    `xml:"state"`
	Owner    Owner    `xml:"owner"`
	Service  Service  `xml:"service"`
	Scripts  []Script `xml:"script"`
}

// State contains information about a given ports
// status. State will be open, closed, etc.
type State struct {
	State     string `xml:"state,attr"`
	Reason    string `xml:"reason,attr"`
	ReasonTTL string `xml:"reason_ttl,attr"`
	ReasonIP  string `xml:"reason_ip,attr"`
}

// Owner contains the name of Port.Owner.
type Owner struct {
	Name string `xml:"name,attr"`
}

// Service contains detailed information about a Port's
// service details.
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

// Script contains information from Nmap Scripting Engine.
type Script struct {
	Id     string `xml:"id,attr"`
	Output string `xml:"output,attr"`
}

// Os contains the fingerprinted operating system for a Host.
type Os struct {
	PortUsed      []PortUsed      `xml:"portused"`
	OsMatch       []OsMatch       `xml:"osmatch"`
	OsFingerprint []OsFingerprint `xml:"osfingerprint"`
}

// PortUsed is the port used to fingerprint a Os.
type PortUsed struct {
	State  string `xml:"state,attr"`
	Proto  string `xml:"proto,attr"`
	PortId string `xml:"portid,attr"`
}

// OsMatch contains detailed information regarding a Os fingerprint.
type OsMatch struct {
	Name     string    `xml:"name,attr"`
	Accuracy string    `xml:"accuracy,attr"`
	Line     string    `xml:"line,attr"`
	OsClass  []OsClass `xml:"osclass"`
}

// OsClass contains vendor information for an Os.
type OsClass struct {
	Vendor   string `xml:"vendor,attr"`
	OsGen    string `xml"osgen,attr"`
	Type     string `xml:"type,attr"`
	Accuracy string `xml:"accurancy,attr"`
	OsFamily string `xml:"osfamily,attr"`
}

// OsFingerprint is the actual fingerprint string.
type OsFingerprint struct {
	Fingerprint string `xml:"fingerprint,attr"`
}

// Distance is the amount of hops to a particular host.
type Distance struct {
	Value string `xml:"value,attr"`
}

// Uptime is the amount of time the host has been up.
type Uptime struct {
	Seconds  string `xml:"seconds,attr"`
	Lastboot string `xml:"lastboot,attr"`
}

// TcpSequence contains information regarding the detected tcp sequence.
type TcpSequence struct {
	Index      string `xml:"index,attr"`
	Difficulty string `xml:"difficulty,attr"`
	Values     string `xml:"vaules,attr"`
}

// IPIdSequence contains information regarding the detected ip sequence.
type IPIdSequence struct {
	Class  string `xml:"class,attr"`
	Values string `xml:"values,attr"`
}

// Times contains time statistics for an Nmap scan.
type Times struct {
	Srtt   string `xml:"srtt,attr"`
	Rttvar string `xml:"rttvar,attr"`
	To     string `xml:"to,attr"`
}

// Trace contains the hops to a Host.
type Trace struct {
	Hops []Hop `xml:"hop"`
}

// Hop is a ip hop to a Host.
type Hop struct {
	TTL    string `xml:"ttl,attr"`
	Rtt    string `xml:"rtt,attr"`
	IPAddr string `xml:"ipaddr,attr"`
	Host   string `xml:"host,attr"`
}

// RunStats contains statistics for a
// finished Nmap scan.
type RunStats struct {
	Finished Finished `xml:"finished"`
	Hosts    Stats    `xml:"hosts"`
}

// Finished contains detailed statistics regarding
// a finished Nmap scan.
type Finished struct {
	Time     string `xml:"time,attr"`
	TimeStr  string `xml:"timestr,attr"`
	Elapsed  string `xml:"elapsed,attr"`
	Summary  string `xml:"summary,attr"`
	Exit     string `xml:"exit,attr"`
	ErrorMsg string `xml:"errormsg,attr"`
}

// Stats contains the amount of up and down hosts and the total count.
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
