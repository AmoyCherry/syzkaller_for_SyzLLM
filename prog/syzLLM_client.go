package prog

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/google/syzkaller/pkg/log"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
)

type ServerConfig struct {
	Port     string
	Host     string
	HostName string
}

func getServerConfig() ServerConfig {
	var parallel = ServerConfig{
		Port:     "6678",
		Host:     "10.211.55.4",
		HostName: "parallel",
	}

	return parallel
}

func InsertMaskToSequence(sequence []string, position int) []string {
	return Insert(sequence, MASK, position)
}

func Insert(sequence []string, target string, position int) []string {
	if position < 0 || position >= len(sequence) {
		position = len(sequence)
	}

	result := append(sequence[:position], append([]string{target}, sequence[position:]...)...)
	return result
}

const MASK = "[MASK]"

type SyscallData struct {
	Syscalls []string
}

type SyzLLMResponse struct {
	State   int
	Syscall string
}

func enableCalls(program *Prog, table *ChoiceTable) {
	for idx, call := range program.Calls {
		if !table.Enabled(call.Meta.ID) {
			table.runs[call.Meta.ID] = make([]int32, max(1, len(table.target.Syscalls)))
			for i := range table.runs[call.Meta.ID] {
				table.runs[call.Meta.ID][i] = 1
			}
			table.noGenerateCalls[call.Meta.ID] = true
			// remove previous calls
		}
		if call.Props.Rerun > 0 && call.Props.FailNth > 0 {
			if idx%2 == 0 {
				call.Props.Rerun = 0
			} else {
				call.Props.FailNth = 0
			}
		}

	}
}

func (ctx *mutator) requestNewCallAsync(program *Prog, insertPosition int, choiceTable *ChoiceTable) []*Call {
	normalizedMaskedSyscallList, maskedSyscallList := addMaskToCalls(program, insertPosition)
	jsonData, err := json.Marshal(SyscallData{Syscalls: normalizedMaskedSyscallList})
	if err != nil {
		fmt.Println("Error marshaling JSON:", err)
		return program.Calls
	}

	var serviceConfig = getServerConfig()
	url := fmt.Sprintf("http://%s:%s", serviceConfig.Host, serviceConfig.Port)
	client := GetClient()
	resp, err := client.SendPostRequest(url, jsonData)
	if err != nil {
		fmt.Println("Error reading response:", err)
		return program.Calls
	}
	defer resp.Body.Close()

	responseByte, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Error reading response:", err)
		return program.Calls
	}

	//var syzLLMResponse SyzLLMResponse
	syzLLMResponse := SyzLLMResponse{-1, ""}
	err = json.Unmarshal(responseByte, &syzLLMResponse)
	if err != nil {
		fmt.Println("Error unmarshaling response:", err)
		return program.Calls
	}
	if syzLLMResponse.State != 0 {
		return program.Calls
	}

	newCall := syzLLMResponse.Syscall
	calls := ParseResource(newCall, maskedSyscallList, insertPosition)
	newSyscallSequence := ""
	for _, call := range calls {
		if len(newSyscallSequence) > 0 {
			newSyscallSequence += "\n"
		}
		newSyscallSequence += call
	}
	newSyscallBytes := []byte(newSyscallSequence)
	newProg, err := program.Target.Deserialize(newSyscallBytes, NonStrict)
	if err != nil {
		return program.Calls
	}

	enableCalls(newProg, choiceTable)

	return newProg.Calls
}

type Client struct {
	client *http.Client
	once   sync.Once
}

var instance *Client

func GetClient() *Client {
	if instance == nil {
		instance = &Client{}
		instance.once.Do(func() {
			instance.client = &http.Client{}
		})
	}
	return instance
}

func (c *Client) SendPostRequest(url string, jsonData []byte) (*http.Response, error) {
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		fmt.Println("Error sending JSON:", err)
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		fmt.Println("Error reading response:", err)
		return nil, err
	}

	return resp, nil
}

const (
	RPrefix = "@RSTART@"
	RSuffix = "@REND@"
)

var re = regexp.MustCompile(regexp.QuoteMeta(RPrefix) + "(.*?)" + regexp.QuoteMeta(RSuffix))

// ParseResource
// replace Prefix-Call-Suffix to r-
func ParseResource(call string, calls []string, insertPosition int) []string {
	var providerText string
	ParseInner := func(prefixedName string, name string, extractedCall string) string {
		resCount := 0
		for i, c := range calls {
			if HasResource(c) {
				resCount += 1
			}
			startIdx := strings.Index(c, prefixedName)
			if startIdx != -1 && i < insertPosition {
				res := c[0:startIdx]
				return res
			}
			if i >= insertPosition {
				res := "r" + strconv.Itoa(resCount)
				providerText = res + " = " + extractedCall
				return res
				/*s := newState(r.target, r.target.DefaultChoiceTable(), nil)
				meta, exist := GetCallMetaInstance().Get(name)
				if !exist {
					return ""
				}
				resProvider := r.generateParticularCall(s, meta)
				p := &Prog{
					Target:   r.target,
					Calls:    resProvider,
					Comments: nil,
				}
				providerText := strings.Split(string(p.Serialize()[:]), "\n")
				for _, callText := range providerText {
					idx := strings.Index(callText, prefixedName)
					if idx != -1 {
						resProviders = append(resProviders, providerText...)
						res := callText[0:idx]
						return res
					}
				}
				return ""*/
			}
		}
		return ""
	}

	parsedCall := re.ReplaceAllStringFunc(call, func(match string) string {
		submatch := re.FindStringSubmatch(match)
		if submatch == nil || len(submatch) < 2 {
			return match
		}
		// submatch should look like open$at(0x111, ...)
		callName := ExtractCallName(submatch[1])
		return ParseInner(" = "+callName, callName, submatch[1])
	})
	parsedCall = UpdateResourceCount(parsedCall, calls, insertPosition, len(providerText) > 0)

	calls[insertPosition] = parsedCall
	if len(providerText) > 0 {
		calls = append(calls[:insertPosition], append([]string{providerText}, calls[insertPosition:]...)...)
	}
	return calls
}

var CallNamePattern = regexp.MustCompile(`^([a-zA-Z0-9_$]+)\(`)

func ExtractCallName(call string) string {
	match := CallNamePattern.FindStringSubmatch(call)

	if len(match) > 1 {
		return match[1]
	} else {
		log.Fatalf("wrong resource call")
	}
	return ""
}

func HasResource(call string) bool {
	if call[0] != 'r' {
		return false
	}
	for _, c := range call {
		switch c {
		case '(':
			return false
		case '=':
			return true
		default:
			continue
		}
	}
	return false
}

func UpdateResourceCount(call string, calls []string, insertPosition int, hasProvider bool) string {
	resCount := 0
	for i, c := range calls {
		if i >= insertPosition {
			break
		}
		if HasResource(c) {
			resCount += 1
		}
	}

	offset := 0
	if hasProvider {
		resCount += 1
		offset += 1
	}

	if HasResource(call) {
		call = AssignResource(call, resCount)
		offset += 1
	}

	for i := insertPosition + 1; offset > 0 && i < len(calls); i++ {
		resNumber, hasRes := ExtractResourceNumber(calls[i])
		if hasRes {
			calls[i] = AssignResource(calls[i], resNumber+offset)
			for j := i + 1; j < len(calls); j++ {
				calls[j] = strings.Replace(calls[j], "r"+strconv.Itoa(resNumber)+",", "r"+strconv.Itoa(resNumber+offset)+",", -1)
				calls[j] = strings.Replace(calls[j], "r"+strconv.Itoa(resNumber)+")", "r"+strconv.Itoa(resNumber+offset)+")", -1)
				calls[j] = strings.Replace(calls[j], "r"+strconv.Itoa(resNumber)+"}", "r"+strconv.Itoa(resNumber+offset)+"}", -1)
			}
		}
	}

	return call
}

var ResourcePattern = regexp.MustCompile(`^r\d+`)

func AssignResource(call string, resNumber int) string {
	newNumberStr := "r" + strconv.Itoa(resNumber)
	result := ResourcePattern.ReplaceAllString(call, newNumberStr)

	return result
}

var ResNumberPattern = regexp.MustCompile(`^r(\d+)`)

func ExtractResourceNumber(call string) (int, bool) {
	match := ResNumberPattern.FindStringSubmatch(call)

	hasRes := true
	if len(match) < 2 {
		hasRes = false
		return 0, hasRes
	}

	number, err := strconv.Atoi(match[1])
	if err != nil {
		log.Fatalf("failed to convert number: %v", err)
	}

	return number, hasRes
}

func addMaskToCalls(program *Prog, insertPosition int) ([]string, []string) {
	syscallList := parseProgToSlice(program)

	TryNormalizeArgs(program)
	normalizedSyscallList := parseProgToSlice(program)

	for i, call := range normalizedSyscallList {
		normalizedSyscallList[i] = ConvertAnyBlob(call)
	}

	return InsertMaskToSequence(normalizedSyscallList, insertPosition), InsertMaskToSequence(syscallList, insertPosition)
}

func parseProgToSlice(program *Prog) []string {
	syscallBytes := program.Serialize()
	syscallList := strings.Split(string(syscallBytes[:]), "\n")
	if syscallList[len(syscallList)-1] == "" {
		syscallList = syscallList[:len(syscallList)-1]
	}

	return syscallList
}

func max(a int, b int) int {
	if a > b {
		return a
	}
	return b
}

var _addrGeneratorInstance *AddrGenerator
var _addrGeneratorOnce sync.Once

func GetAddrGeneratorInstance() *AddrGenerator {
	_addrGeneratorOnce.Do(func() {
		_addrGeneratorInstance = &AddrGenerator{AddrCounter: make(map[string]uint64), AddrBase: make(map[string]uint64)}
	})
	return _addrGeneratorInstance
}

type AddrGenerator struct {
	AddrCounter map[string]uint64
	AddrBase    map[string]uint64
}

func CopyCounter() map[string]uint64 {
	counter := make(map[string]uint64)
	addrGenerator := GetAddrGeneratorInstance()
	for key, val := range addrGenerator.AddrCounter {
		counter[key] = val
	}
	return counter
}

func NormalizeArgs(program *Prog) {
	for i, call := range program.Calls {
		fields := call.Meta.Args
		for j, _arg := range call.Args {
			switch arg := _arg.(type) {
			case *ResultArg:
				continue
			default:
				argReplacer := NewArgReplacer(call.Meta.Name)
				program.Calls[i].Args[j] = argReplacer.DFSArgs(arg, fields[j])
			}
		}
	}
}

func TryNormalizeArgs(program *Prog) {
	oldProgram := program
	defer func() {
		if r := recover(); r != nil {
			program = oldProgram
		}
	}()
	NormalizeArgs(program)
}

type ArgReplacer struct {
	currentCallName string
	InitAddrCnt     int
	AddrCounter     map[string]uint64
}

func NewArgReplacer(callName string) *ArgReplacer {
	argReplacer := new(ArgReplacer)
	argReplacer.currentCallName = callName
	argReplacer.InitAddrCnt = 0
	argReplacer.AddrCounter = CopyCounter()
	return argReplacer
}

func (a *ArgReplacer) DFSArgs(arg Arg, field Field) Arg {
	switch argType := arg.(type) {
	case *DataArg:
		return a.GenerateDataArg(argType, field.Type)
	case *ConstArg:
		return a.GenerateConstArg(argType, field.Type, field.Name)
	case *UnionArg:
		return a.GenerateUnionArg(argType, field.Type)
	case *PointerArg:
		return a.GeneratePtrArg(argType, field.Type)
	case *GroupArg:
		return a.GenerateGroupArg(argType, field.Type)
	default:
		return arg
	}
}

func (a *ArgReplacer) GenerateDataArg(dataArg *DataArg, fieldType Type) Arg {
	const Path = "./file0\x00"
	const BufferSize = 0x400
	data := make([]byte, 0)

	if dataArg.ArgCommon.Dir() == DirOut {
		return MakeOutDataArg(dataArg.ArgCommon.Type(), dataArg.ArgCommon.Dir(), BufferSize)
	} else if dataArg.ArgCommon.Dir() == DirIn {
		switch ft := fieldType.(type) {
		case *BufferType:
			if ft.Kind == BufferFilename {
				data = []byte(Path)
			} else if len(ft.Values) > 0 {
				data = []byte(ft.Values[0])
			} else {
				data = make([]byte, BufferSize)
				for i := 0; i < BufferSize; i++ {
					data[i] = 0
				}
			}
		}
		return MakeDataArg(dataArg.ArgCommon.Type(), dataArg.ArgCommon.Dir(), data)
	}

	return dataArg
}

// GenerateConstArg some of const values are choose from UnionType.Fields by ConstArg.Index, seems a type of flags
func (a *ArgReplacer) GenerateConstArg(constArg *ConstArg, fieldType Type, fieldName string) Arg {
	const FD = ^uint64(0)
	const NUM = 0x111

	switch fieldType.(type) {
	case *FlagsType:
		return constArg
	default:
		if fieldName == "mode" {
			return constArg
		} else if fieldName == "fd" {
			return MakeConstArg(constArg.ArgCommon.Type(), constArg.ArgCommon.Dir(), FD)
		} else {
			return MakeConstArg(constArg.ArgCommon.Type(), constArg.ArgCommon.Dir(), NUM)
		}
	}
}

func (a *ArgReplacer) GenerateUnionArg(unionArg *UnionArg, fieldType Type) Arg {
	switch ft := fieldType.(type) {
	case *UnionType:
		switch argOption := unionArg.Option.(type) {
		case *DataArg:
			unionArg.Option = a.GenerateDataArg(argOption, ft.Fields[unionArg.Index].Type)
		case *ConstArg:
			unionArg.Option = a.GenerateConstArg(argOption, ft.Fields[unionArg.Index].Type, ft.Fields[unionArg.Index].Name)
		case *PointerArg:
			unionArg.Option = a.GeneratePtrArg(argOption, ft.Fields[unionArg.Index].Type)
		case *GroupArg:
			unionArg.Option = a.GenerateGroupArg(argOption, ft.Fields[unionArg.Index].Type)
		case *UnionArg:
			unionArg.Option = a.GenerateUnionArg(argOption, ft.Fields[unionArg.Index].Type)
		}
	}

	return unionArg
}

func (a *ArgReplacer) GenerateGroupArg(groupArg *GroupArg, fieldType Type) Arg {
	switch ft := fieldType.(type) {
	case *StructType:
		if len(groupArg.Inner) != len(ft.Fields) {
			break
		}

		for i, child := range groupArg.Inner {
			switch child := child.(type) {
			case *DataArg:
				groupArg.Inner[i] = a.GenerateDataArg(child, ft.Fields[i].Type)
			case *ConstArg:
				groupArg.Inner[i] = a.GenerateConstArg(child, ft.Fields[i].Type, ft.Fields[i].Name)
			case *GroupArg:
				groupArg.Inner[i] = a.GenerateGroupArg(child, ft.Fields[i].Type)
			case *PointerArg:
				groupArg.Inner[i] = a.GeneratePtrArg(child, ft.Fields[i].Type)
			case *UnionArg:
				groupArg.Inner[i] = a.GenerateUnionArg(child, ft.Fields[i].Type)
			}
		}
	}

	return groupArg
}

func (a *ArgReplacer) GeneratePtrArg(ptrArg *PointerArg, fieldType Type) Arg {
	addr := a.GetAddr()
	if addr != 0 {
		ptrArg.Address = addr
	}

	switch ft := fieldType.(type) {
	case *PtrType:
		switch ptrRes := ptrArg.Res.(type) {
		case *DataArg:
			ptrArg.Res = a.GenerateDataArg(ptrRes, ft.Elem)
		case *ConstArg:
			ptrArg.Res = a.GenerateConstArg(ptrRes, ft.Elem, "")
		case *GroupArg:
			ptrArg.Res = a.GenerateGroupArg(ptrRes, ft.Elem)
		case *UnionArg:
			ptrArg.Res = a.GenerateUnionArg(ptrRes, ft.Elem)
		case *PointerArg:
			ptrArg.Res = a.GeneratePtrArg(ptrRes, ft.Elem)
		}
	}

	return ptrArg
}

func (a *ArgReplacer) GetAddr() uint64 {
	cnt, ok := a.AddrCounter[a.currentCallName]
	if !ok {
		return 0
	}
	a.AddrCounter[a.currentCallName] += 1

	return GetAddrGeneratorInstance().AddrBase[a.currentCallName] + AddrSameCallStep*cnt
}

const (
	// defined in encoding.go
	BaseAddr         = uint64(0x0)
	AddrSameCallStep = uint64(0x400)
	AddrDiffCallStep = AddrSameCallStep * 4
)

func ConvertAnyBlob(s string) string {
	re := regexp.MustCompile(`@ANYBLOB="([a-zA-Z0-9]+)"`)
	return re.ReplaceAllString(s, ANYBLOB)
}

const ANYBLOB = `@ANYBLOB="02000000bf0100000000000000000000ba010000086e000021232948de042774602f36cddb4aa287b3b3312d91f7fbcd26167f6444b666b5023d6da31997c5864183bb5548c8d5210899d6b5b6d5efcd76ffd06e3e62e26c761a6047d17f3aed967ad2b9eaceeae2cb7df923371fd5e88cb2109310447fd0b311245765d6097e53a8c17cc048956f81eae779bb571cacac48a457bd4d0318be01a875d8a9d7039d2c88658fdc197346946806aca29bd51e448d160dee6cb1b7154b67078c77c404f67883fdeea217dddce5faf01620da79e102ffa9192e2b0b89fc559edd377d1ba0dce6baf4f99d80879756b350f508274acd1cd428d448cf820f4706031e75835813e13b954579822cabf5c49c204788c967997833ccbf197ef5fe6a6fa3b8cc8808fb8af13058263c1f576dad05236f15a8d4d9d46f05a2d510e430f553756fd3aae8cba7bac5f2ca2a3eb779f29b0a7fb6cffc073f9c9d76da64ca91814f1a08c83ab9c767b1f24c59ca4e1fe4e501d3e220cf8146fb7c4a4726a97cd02b93c47222218804eebd1795e9a389f75da01498ff1e648773fb5f475018227e3181a51afc21c91c366668868d18242d62acd0c19e46a20d7e2579880633802e262c359e3a2937675d237339e1abeb27f4ae33d12ffeccb69618e6000356b856433cc859be20e7de9b899d21a99a041c7f689f04c2347549df5412ed2a6fc6f5b8d6d16d81e8474d47ea907603135c43f58f8940fe3fecb80e4b03c63159f827ad5aa2c7cd90bde569cd757832446fa385df7c2202b835c30b1d337b42790ba5e9beb9d4d3b8806e2e978b5db841aff85e17cf8d73874f436bc76f336c123a7cf67e3992ae8f0645bb88d41b9437ce7593451437a1be6b7208faafad77d91ea449f7421228b7d8883e072c2abaaf80681038e15b69e0c7f4868f0cd115fd2607f0f5305114595e04359350c6b0580c5311c4dc7f89c86d3184d9fc1f9cc0250968bad83cc9ae7fa8081a6f47ca9eb7b4697b9c70af9277933c3881ff5fbc5a7264038ce11f170c24009d9d3113fa537207baacf105949e4ee99074bc199acd0b9c14fc63e77a6f54f90584779ac5d7e88ac1fbbd09f880d91c25c77570f42a7c1e6e718c40a7591ae419d5ff1cd0362fa4c9fb7ead87ea540ccfe69565abac2a4a3fd7e1090cdba043c3487c291a6d17cdb50e4ec6e7b0c437527cdecf3fe6e03727ecbb1c0284466431d782dd35c306428e3880379de2c4f47301e5d498035abd0b7a92da78aacfbf91a8ce711ab8cbedfbf45f934d31d15668712873041bb7972b65e807912306e736e08fa8570afef98bcd20c5b627dfa990ff78f1381398bfa0594ab42c00234345463df635fc7f4b5eea378497c53205306e27ae120a903570cdf6ff063797c84f78ded9a4e5a8a6dd40e0295a670624bf2c1e81d4b48a6d904b36accc0f09fdc24d1bfc31c84a9a9e10b2d7b11c78bd5945b0ffdc38f4cdec08c53670340cc778c7ac80bf5a36ca4b618f39b66db6f7a9b7d553af0d68ff41e2fcce96d6fd41373ead8b1d827e97cb281e2e78380e5e8e340d392e60f3125eed1295b07726c74aaebfd35fc927de7613a4c967054b78be29fe2f38d78ad4d24b1dea04125bf738e2a46ab415265d75403e9ef7ab2612389d4d"`

type CallMeta struct {
	mu sync.RWMutex
	m  map[string]*Syscall
}

var _CallMetaInstance *CallMeta
var _CallMetaOnce sync.Once

func GetCallMetaInstance() *CallMeta {
	_CallMetaOnce.Do(func() {
		_CallMetaInstance = &CallMeta{
			m: make(map[string]*Syscall),
		}
	})

	return _CallMetaInstance
}

func (s *CallMeta) Set(key string, value *Syscall) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[key] = value
}

func (s *CallMeta) Get(key string) (*Syscall, bool) {
	//s.mu.RLock()
	//defer s.mu.RUnlock()
	val, exists := s.m[key]
	return val, exists
}
