package constant

// Rule Type
const (
	Domain RuleType = iota
	DomainSuffix
	DomainKeyword
	DomainRegex
	GEOIP
	IPCIDR
	SrcIPCIDR
	SrcPort
	DstPort
	InPort
	InUser
	InName
	InType
	ProcessName
	ProcessPath
	ProcessNameRegex
	ProcessPathRegex
	Network
	Type_
	IPSet
	MATCH
	RuleSet
	DomainTree
	IpCidrTree
	SubRules
	AND
	OR
	NOT
)

type RuleType int

func (rt RuleType) String() string {
	switch rt {
	case Domain:
		return "Domain"
	case DomainSuffix:
		return "DomainSuffix"
	case DomainKeyword:
		return "DomainKeyword"
	case DomainRegex:
		return "DomainRegex"
	case GEOIP:
		return "GeoIP"
	case IPCIDR:
		return "IPCIDR"
	case SrcIPCIDR:
		return "SrcIPCIDR"
	case SrcPort:
		return "SrcPort"
	case DstPort:
		return "DstPort"
	case InPort:
		return "InPort"
	case InUser:
		return "InUser"
	case InName:
		return "InName"
	case InType:
		return "InType"
	case Network:
		return "Network"
	case Type_:
		return "Type"
	case ProcessName:
		return "ProcessName"
	case ProcessPath:
		return "ProcessPath"
	case ProcessNameRegex:
		return "ProcessNameRegex"
	case ProcessPathRegex:
		return "ProcessPathRegex"
	case IPSet:
		return "IPSet"
	case MATCH:
		return "Match"
	case RuleSet:
		return "RuleSet"
	case DomainTree:
		return "DomainTree"
	case IpCidrTree:
		return "IpCidrTree"
	case SubRules:
		return "SubRules"
	case AND:
		return "AND"
	case OR:
		return "OR"
	case NOT:
		return "NOT"
	default:
		return "Unknown"
	}
}

type Rule interface {
	RuleType() RuleType
	Match(metadata *Metadata) (bool, string)
	Adapter() string
	Payload() string
	ShouldResolveIP() bool
	ShouldFindProcess() bool
}
