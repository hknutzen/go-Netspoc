package jcode

// JSON format of intermediate code written by pass1 and read by pass2.
type RouterData struct {
	Model         string     `json:"model"`
	ACLs          []*ACLInfo `json:"acls"`
	FilterOnly    []string   `json:"filter_only"`
	DoObjectgroup int        `json:"do_objectgroup"`
	LogDeny       string     `json:"log_deny"`
}

type ACLInfo struct {
	Name         string   `json:"name"`
	IsStdACL     int      `json:"is_std_acl"`
	IntfRules    []*Rule  `json:"intf_rules"`
	Rules        []*Rule  `json:"rules"`
	OptNetworks  []string `json:"opt_networks"`
	NoOptAddrs   []string `json:"no_opt_addrs"`
	NeedProtect  []string `json:"need_protect"`
	FilterAnySrc int      `json:"filter_any_src"`
	IsCryptoACL  int      `json:"is_crypto_acl"`
	AddPermit    int      `json:"add_permit"`
	AddDeny      int      `json:"add_deny"`
}

type Rule struct {
	Deny         int      `json:"deny"`
	Src          []string `json:"src"`
	Dst          []string `json:"dst"`
	Prt          []string `json:"prt"`
	SrcRange     string   `json:"src_range"`
	Log          string   `json:"log"`
	OptSecondary int      `json:"opt_secondary"`
}
