package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"

	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/report"
)

func main() {
	var (
		flagInput  = flag.String("i", "", "input: path of a raw bug report")
		flagOutput = flag.String("o", "", "output: path of a decent bug report")
		flagUsage  = flag.Bool("u", false, "Get the usage")
		flagConfig = flag.String("cfg", "", "Path of syzkaller config")
	)
	flag.Parse()
	if *flagInput == "" || *flagConfig == "" || *flagOutput == "" || *flagUsage {
		fmt.Printf("Usage:  syz-logparser -cfg path2cfg -i path2log -o path2write\n")
		return
	}

	cfg, err := mgrconfig.LoadFile(*flagConfig)
	if err != nil {
		fmt.Println(err)
		return
	}
	output := loadLog(*flagInput)
	if len(output) == 0 {
		fmt.Printf("No bug report found in the given path\n")
		return
	}
	rep, err := report.NewReporter(cfg)
	if err != nil {
		fmt.Println(err)
		return
	}
	report := rep.Parse(output)
	if err := rep.Symbolize(report); err != nil {
		fmt.Println(err)
		return
	}

	if !writeLog(*flagOutput, report.Report) {
		fmt.Println("Fail to write to the given path")
		return
	}
}

func loadLog(path string) []byte {
	var output []byte

	logFile, err := os.Open(path)
	if err != nil {
		fmt.Println(err)
		return output
	}
	r := bufio.NewReader(logFile)
	for {
		ln, _, err := r.ReadLine()
		if ln == nil {
			break
		}
		if err != nil {
			fmt.Println(err)
			break
		}
		ln = append(ln, '\n')
		output = append(output, ln...)
	}
	logFile.Close()
	return output
}

func writeLog(path string, output []byte) bool {
	logFile, err := os.Create(path)
	if err != nil {
		fmt.Println(err)
		return false
	}
	w := bufio.NewWriter(logFile)
	w.Write(output)
	w.Flush()
	logFile.Close()
	return true
}
