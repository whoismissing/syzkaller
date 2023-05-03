package main

import (
	"bufio"
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/symbolizer"
)

type Range struct {
	Funcname string
	Start    uint64
	End      uint64
	File     string
	Line     int
	Found    bool
}

type BranchNode struct {
	followBy uint64
	jumpTo   uint64
}

type TraceInfo struct {
	File string
	Line int
}

type Trace struct {
	condJump    TraceInfo
	correctPath TraceInfo
	wrongPath   TraceInfo
}

var branch map[uint64]map[string]uint64
var trace []Trace

func main() {
	var (
		f_funcname    = flag.String("f", "", "Funcname")
		f_vmlinuxPath = flag.String("v", "", "Path to vmlinux")
		f_rawformat   = flag.Bool("r", false, "Parsing the raw vmlinux.")
		f_dCache      = flag.String("d", "", "Delete an cache, follow by the path to vmlinux")
		f_usage       = flag.Bool("u", false, "Get the usage")
		f_strict      = flag.Bool("s", false, "Strictly match")
		fTrace        = flag.String("t", "", "Path to trace file")
		targetOS      = flag.String("-os", "linux", "OS of target, default as linux")
		targetArch    = flag.String("-arch", "amd64", "arch of target, default as amd64")
	)
	flag.Parse()
	if (*f_vmlinuxPath == "" && *f_dCache == "" && *fTrace == "") || (*f_usage) {
		fmt.Printf("Usage:  syz-func2addr [-r] [-d path_of_vmlinux] [-f funcname [-v path_of_vmlinux]]\n    eg. syz-func2addr -f snprintf_int_array -v /home/user/linux/vmlinux -r -s\n")
		return
	}
	if !buildTrace(*fTrace) {
		fmt.Printf("Fail to build trace")
		return
	}
	branch = make(map[uint64]map[string]uint64)
	var n uint64
	n = 0
	var list []Range
	list = append(list, Range{Start: 0x0, End: 0x0, Found: false})

	cache_exist, cache_path := isCacheExist(*f_dCache, *f_vmlinuxPath)
	if *f_dCache != "" {
		if cache_exist {
			_ = os.Remove(cache_path)
		}
		return
	}

	var frames []symbolizer.Frame
	if cache_exist {
		frames, branch = openAndParseCache(cache_path)
		fmt.Printf("Found cache...\n")
	} else {
		pcs, _ := coveredPcs(*targetArch, *f_vmlinuxPath, *f_rawformat)
		if len(pcs) == 0 {
			fmt.Printf("It seems vmlinux doesn't have any <__sanitizer_cov_trace_pc> functions. Try '-r' argument\n")
			cache_exist = true
		}
		fmt.Printf("Scan OK\n")
		frames, _, _ = symbolize(*f_vmlinuxPath, pcs, *targetArch, *targetOS)
		fmt.Printf("Symbolize OK\n")
	}

	for _, frame := range frames {
		if (strings.Contains(frame.Func, *f_funcname) && *f_strict == false) ||
			(frame.Func == *f_funcname && *f_strict == true) {
			if list[n].Found == false {
				list[n].Funcname = frame.Func
				list[n].Start = frame.PC
				list[n].End = frame.PC
				list[n].Line = frame.Line
				list[n].File = frame.File
				list[n].Found = true
			} else {
				list[n].End = frame.PC
			}
		} else if frame.Inline != true && frame.Func != *f_funcname && list[n].Found == true {
			list = append(list, Range{Start: 0x0, End: 0x0, Found: false})
			n++
		}
		if node, ok := branch[frame.PC]; ok {
			for _, e := range trace {
				if stripPrefix(frame.File) == e.condJump.File && frame.Line == e.condJump.Line {
					followBy := node["followBy"]
					jumpTo := node["jumpTo"]
					r, _, _ := symbolize(*f_vmlinuxPath, []uint64{followBy}, *targetArch, *targetOS)
					TFile := r[0].File
					TLine := r[0].Line
					r, _, _ = symbolize(*f_vmlinuxPath, []uint64{jumpTo + 5}, *targetArch, *targetOS) //A potential bug here is that the next inst is jmp xxx, need a special checker
					FFile := r[0].File
					FLine := r[0].Line
					if stripPrefix(TFile) == e.correctPath.File && stripPrefix(FFile) == e.correctPath.File {
						fmt.Printf("%d %d %d\n", TLine, FLine, e.correctPath.Line)
						if TLine <= e.correctPath.Line && FLine > e.correctPath.Line {
							//True
							fmt.Printf("cond: %x correct: %x wrong: %x\n", frame.PC, followBy, jumpTo)
						}
						if FLine <= e.correctPath.Line {
							//False
							fmt.Printf("cond: %x correct: %x wrong: %x\n", frame.PC, jumpTo, followBy)
						}
					}
				}
			}

		}
	}

	if cache_exist == false {
		data1, _ := json.Marshal(frames)
		data2, _ := json.Marshal(branch)
		data1 = append(data1, []byte("\n")...)
		data := append(data1, data2...)
		createAndWriteCache(cache_path, data)
	}
	list = list[0 : len(list)-1 : len(list)]
	for _, e := range list {
		fmt.Printf("Function:%s\nStart:%x\nEnd:%x\nLocation:%s:%d\nFound:%t\n", e.Funcname, e.Start, e.End, e.File, e.Line, e.Found)
	}
}

var prefix = ""

func stripPrefix(path string) string {
	parts := strings.Split(path, "/")
	if prefix != "" {
		r := strings.Split(path, prefix)
		if len(r) == 2 {
			return r[1]
		}
	}
	for i := len(parts) - 1; i >= 0; i-- {
		if parts[i] == "linux" {
			prefix = strings.Join(parts[:i+1], "/") + "/"
			return strings.Join(parts[i+1:], "/")
		}
	}
	return path
}

func buildTrace(path2Trace string) bool {
	var file string
	var line int
	traceFile, err := os.Open(path2Trace)
	if err != nil {
		fmt.Println(err)
		return false
	}
	r := bufio.NewReader(traceFile)
	for {
		ln, _, err := r.ReadLine()
		if ln == nil {
			return true
		}
		if err != nil {
			fmt.Println(err)
			return false
		}
		space := bytes.IndexByte(ln, ' ')
		file, line = parseTrace(ln[:space])
		condJump := TraceInfo{File: file, Line: line}
		file, line = parseTrace(ln[space+1:])
		correctPath := TraceInfo{File: file, Line: line}
		trace = append(trace, Trace{condJump: condJump, correctPath: correctPath})
	}
}

func parseTrace(line []byte) (string, int) {
	colon := bytes.IndexByte(line, ':')
	val, _ := strconv.Atoi(string(line[colon+1:]))
	return string(line[:colon]), val
}

func getFrameByPc(base int, frames []symbolizer.Frame, pc uint64) (string, int) {
	for i := base; i < len(frames); i++ {
		if frames[i].PC == pc {
			return frames[i].File, frames[i].Line
		}
	}
	return "", -1
}

func coveredPcs(arch, bin string, rawformat bool) ([]uint64, error) {
	cmd := osutil.Command("objdump", "-d", "--no-show-raw-insn", bin)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	defer stdout.Close()
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	defer cmd.Wait()
	var pcs []uint64
	s := bufio.NewScanner(stdout)

	iBase := 18
	var jumpTo, addr uint64
	jumpTo = 0
	addr = 0
	for s.Scan() {
		ln := s.Bytes()
		colon := bytes.IndexByte(ln, ':')
		if colon == -1 {
			continue
		}
		pc, err := strconv.ParseUint(string(ln[:colon]), 16, 64)
		if err != nil {
			continue
		}
		//find a conditional jump

		if jumpTo != 0 && addr != 0 {
			branch[addr] = map[string]uint64{"jumpTo": jumpTo, "followBy": pc}
			jumpTo = 0
			addr = 0
		}
		if ln[iBase] == 'j' {
			if pos := bytes.Index(ln, []byte("jmp")); pos != -1 {
				continue
			}
			pos := bytes.Index(ln[iBase:], []byte("f"))
			if (pos != -1) && (len(ln[iBase:]) > pos+16) {
				jumpTo, err = strconv.ParseUint(string(ln[pos+iBase:pos+iBase+16]), 16, 64)
				if err != nil {
					continue
				}
				addr = pc
			}
			pcs = append(pcs, pc)
		}
	}
	if err := s.Err(); err != nil {
		return nil, err
	}
	return pcs, nil
}

func symbolize(vmlinux string, pcs []uint64, arch, os string) ([]symbolizer.Frame, string, error) {
	symb := symbolizer.NewSymbolizer()
	defer symb.Close()

	frames, err := symb.SymbolizeArray(vmlinux, pcs)
	if err != nil {
		return nil, "", err
	}

	return frames, "", nil
}

func openAndParseCache(path string) ([]symbolizer.Frame, map[uint64]map[string]uint64) {
	var frame []symbolizer.Frame
	branch := make(map[uint64]map[string]uint64)

	jsonFile, err := os.Open(path)
	if err != nil {
		fmt.Println(err)
		return nil, nil
	}
	data, _ := ioutil.ReadAll(jsonFile)
	newln := bytes.IndexByte(data, '\n')

	json.Unmarshal([]byte(data[:newln]), &frame)
	json.Unmarshal([]byte(data[newln+1:]), &branch)
	jsonFile.Close()
	return frame, branch
}

func createAndWriteCache(path string, data []byte) {
	jsonFile, err := os.Create(path)
	if err != nil {
		fmt.Println(err)
		return
	}
	jsonFile.Write(data)
	jsonFile.Close()
}

func isCacheExist(_dCache, _vmlinuxPath string) (bool, string) {
	dir, err := filepath.Abs(filepath.Dir(os.Args[0]))
	if err != nil {
		log.Fatal(err)
	}
	cache_base := dir + "/fun2addr_cache"
	if _, err := os.Stat(cache_base); os.IsNotExist(err) {
		var mode os.FileMode
		mode = 0755
		os.Mkdir(cache_base, mode)
	}
	h := md5.New()
	if _dCache != "" {
		h.Write([]byte(_dCache))
	} else {
		h.Write([]byte(_vmlinuxPath))
	}
	hash := hex.EncodeToString(h.Sum(nil))
	cache_path := cache_base + "/" + string(hash[:len(hash)])
	if _, err := os.Stat(cache_path); os.IsNotExist(err) {
		return false, cache_path
	}
	return true, cache_path
}
