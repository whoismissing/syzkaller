package courier

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path"

	"github.com/google/syzkaller/pkg/log"
)

var AnalyzerPath string
var ConfirmedSuccess = false

func AppendTestcase(testcase, pocProg []byte, nOfCalls int) {
	AppendMutatingQueue(testcase, pocProg, nOfCalls)
}

func RemoveComments(text []byte) []byte {
	var res []byte
	start := 0
	lines := bytes.SplitAfter(text, []byte("\n"))
	for i, line := range lines {
		if line[0] != '#' {
			start = i
			break
		}
	}
	for i := start; i < len(lines); i++ {
		res = append(res, lines[i]...)
	}
	return res
}

func checkDuplication(hash string, f *os.File) bool {
	line := make([]byte, 8)
	for {
		n, err := f.Read(line)
		if n == 0 && err == io.EOF {
			break
		}
		if err != nil {
			fmt.Printf("Fail to read: %v\n", err)
			return true
		}
		if string(line[:len(line)-1]) == hash {
			return true
		}
	}
	return false
}

func SaveToFile(filename string) {
	hash := path.Base(AnalyzerPath)
	work := path.Dir(path.Dir(AnalyzerPath))
	success := path.Join(work, filename)
	f, err := os.OpenFile(success, os.O_APPEND|os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		log.Logf(0, "Fail to open %s: %v", success, err)
		return
	}
	defer f.Close()
	if !checkDuplication(hash, f) {
		log.Logf(0, "Write %s to %s", filename, success)
		f.WriteString(hash + "\n")
	}
}
