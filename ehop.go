//Package ehop contains untility functions for working with an extrahop
package ehop

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
)

type EDA struct {
	APIKey, hostname string
}

type EXAQuery struct {
	From    int            `json:"from"`
	Records []ExaIcaRecord `json:"records"`
	Total   int            `json:"total"`
	Until   int            `json:"until"`
}

type ExaIcaRecord struct {
	ID     string   `json:"_id"`
	Index  string   `json:"_id"`
	Score  string   `json:"_score"`
	Source IcaClose `json:"_source"`
	Type   string   `json:"_type"`
}

type MetricsTotalByGroup struct {
	Stats  []Stat `json:"stats"`
	Cycle  string `json:"cycle"`
	NodeID int    `json:"node_id"`
	From   int    `json:"from"`
	Until  int    `json:"until"`
}

type Stat struct {
	OID      int       `json:"oid"`
	Time     int       `json:"time"`
	Duration int       `json:"duration"`
	Values   [][]Value `json:"values"`
}

type Value struct {
	Key   KeyDetail     `json:"key"`
	Vtype string        `json:"vtype"`
	Value []ValueDetail `json:"value"`
}

type ValueDetail struct {
	Key   ValueKeyDetail `json:"key"`
	Vtype string         `json:"vtype"`
	Value int            `json:"value"`
}
type KeyDetail struct {
	KeyType string `json:"key_type"`
	Str     string `json:"str"`
}

type ValueKeyDetail struct {
	Key_type  string `json:"key_type"`
	DeviceOID int    `json:"device_oid"`
	Addr      string `json:"addr"`
	Host      string `json:"host"`
	Str       string `json:"str"`
}

type Device struct {
	ModTime       int    `json:"mod_time"`
	NodeID        int    `json:"node_id"`
	ID            int    `json:"id"`
	ExtrahopID    string `json:"extrahop_id"`
	DisplayName   string `json:"display_name"`
	Description   string `json:"description"`
	UserModTime   int    `json:"user_mod_time"`
	DiscoverTime  int    `json:"discover_time"`
	Vlanid        int    `json:"vlanid"`
	ParentID      int    `json:"parent_id"`
	Macaddr       string `json:"macaddr"`
	Vendor        string `json:"vendor"`
	IsL3          bool   `json:"is_l3"`
	Ipaddr4       string `json:"ipaddr4"`
	Ipaddr6       string `json:"ipaddr6"`
	DeviceClass   string `json:"device_class"`
	DefaultName   string `json:"default_name"`
	CustomName    string `json:"custom_name"`
	CdpName       string `json:"cdp_name"`
	DhcpName      string `json:"dhcp_name"`
	Netbios       string `json:"netbios_name"`
	DNSName       string `json:"dns_name"`
	CustomType    string `json:"custom_type"`
	AnalysisLevel int    `json:"analysis_level"`
}

type IcaClose struct {
	Application     ApiObject   `json:"application"`
	FlowId          string      `json:"flowId"`
	Client          interface{} `json:"client"`
	ClientAddr      ApiObject   `json:"clientAddr"`
	ClientPort      int         `json:"clientPort"`
	Server          ApiObject   `json:"server"`
	ServerAddr      ApiObject   `json:"serverAddr"`
	ServerPort      int         `json:"serverPort"`
	ClientZeroWnd   int         `json:"clientZeroWnd"`
	ServerZeroWnd   int         `json:"serverZeroWnd"`
	AuthDomain      string      `json:"authDomain"`
	Host            string      `json:"host"`
	User            string      `json:"user"`
	IsAborted       bool        `json:"isAborted"`
	IsCleanShutdown bool        `json:"isCleanShutdown"`
	IsEncrypted     bool        `json:"isEncrypted"`
	IsSharedSession bool        `json:"isSharedSession"`
	LaunchParams    string      `json:"launchParams"`
	LoadTime        int         `json:"loadTime"`
	LoginTime       int         `json:"loginTime"`
	RoundTripTime   int         `json:"roundTripTime"`
	ClientBytes     int         `json:"clientBytes"`
	ClientL2Bytes   int         `json:"clientL2Bytes"`
	ClientPkts      int         `json:"clientPkts"`
	ClientRTO       int         `json:"clientRTO"`
	ClientType      string      `json:"clientType"`
	ServerBytes     int         `json:"serverBytes"`
	ServerL2Bytes   int         `json:"serverL2Bytes"`
	ServerPkts      int         `json:"serverPkts"`
	ServerRTO       int         `json:"serverRTO"`
	Vlan            int         `json:"vlan"`
	Program         string      `json:"program"`
}

//Metric object from the RecordFormat json object
type Metric struct {
	DisplayName    string `json:"display_name"`
	Name           string `json:"name"`
	DataType       string `json:"data_type"`
	MetaType       string `json:"meta_type"`
	DefaultVisible string `json:"default_visible"`
	Description    string `json:"description"`
}

type ApiObject struct {
	Type  string   `json:"type"`
	Value []string `json:"value"`
}

func NewEDAfromKey(key string) *EDA {
	ehop := new(EDA)
	jsonData := make(map[string]string)
	keyfile, err := ioutil.ReadFile(key)
	if err != nil {
		fmt.Printf("Could not find keys file", err.Error())
	} else if err := json.NewDecoder(bytes.NewReader(keyfile)).Decode(&jsonData); err != nil {
		fmt.Printf("Keys file is in wrong format", err.Error())
	} else {
		for key, value := range jsonData {
			ehop.APIKey = value
			ehop.hostname = key
		}
	}
	return ehop
}

func NewEDA(APIKey string, hostname string) *EDA {
	ehop := new(EDA)
	ehop.APIKey = APIKey
	ehop.hostname = hostname
	return ehop
}

// CreateEhopRequest creates and sends HTTP request to ExtraHop system.  Returns the response
func CreateEhopRequest(method string, call string, payload string, ehop *EDA) (*http.Response, error) {

	path := "https://" + ehop.hostname + "/api/v1/"
	APIKey := "ExtraHop apikey=" + ehop.APIKey

	//Create a 'transport' object... this is necessary if we want to ignore
	//the EH insecure CA.  Similar to '--insecure' option for curl
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	//Crate a new client object... and pass him the parameters of the transport object
	//we created above
	client := http.Client{Transport: tr}
	postBody := []byte(payload)
	req, err := http.NewRequest(method, path+call, bytes.NewBuffer(postBody))
	if err != nil {
		return nil, err
	}

	//Add some header stuff to make it EH friendly
	req.Header.Add("Authorization", APIKey)
	req.Header.Add("Content-Type", " application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	return resp, nil
}
