package main

import (
	"io/ioutil"
	"math/rand"
	_ "net/http/pprof"
	"os"
	"time"

	"github.com/google/syzkaller/courier"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/rpctype"
	"github.com/google/syzkaller/prog"
)

var TestcasePath string
var flagParseTestcase = false
var flagExtraMutating = false

//Read and parse testcase, send it to fuzzer
func (mgr *Manager) parseCustomizedTestcase(a rpctype.GetCallsFromFuzzerArgs, ch chan int) {
	if flagParseTestcase {
		ch <- 0
		return
	}
	flagParseTestcase = true
	var corpus []*prog.Prog
	info, err := os.Stat(TestcasePath)
	if !os.IsNotExist(err) {
		if !info.IsDir() {
			fileCache, err := os.Open(TestcasePath)
			if err != nil {
				log.Logf(0, "Error occur at parseCustomizedTestcase: %v\n", err)
				ch <- 1
				return
			}
			defer fileCache.Close()
			testcase_raw, err := ioutil.ReadFile(TestcasePath)
			if err != nil {
				log.Logf(0, "Error occur at parseCustomizedTestcase: %v\n", err)
				ch <- 1
				return
			}
			testcase := courier.RemoveComments(testcase_raw)
			log.Logf(0, "testcase: %s\n", testcase)
			calls := make(map[*prog.Syscall]bool)
			rnd := rand.New(rand.NewSource(time.Now().UnixNano() + int64(4)*1e12))
			for _, id := range a.EnabledCalls[a.Sandbox] {
				calls[mgr.target.Syscalls[id]] = true
			}
			prios := mgr.target.CalculatePriorities(corpus)
			choiceTable := mgr.target.BuildChoiceTable(prios, calls)

			p, err := mgr.target.Deserialize(testcase, prog.NonStrict)
			if err != nil {
				createTemplatePatch(mgr.cfg.Syzkaller)
				log.Logf(0, "Fail to parse testcase: %v\n", err)
				ch <- -1
				return
			}
			prog.NOfCalls = len(p.Calls)
			prog.PocProg = string(testcase)
			courier.AppendTestcase(testcase, testcase, prog.NOfCalls)
			for i := 1; i < 500; i++ {
				p := p.Clone()
				p.Mutate(rnd, prog.RecommendedCalls, choiceTable, corpus)
				courier.AppendTestcase(p.Serialize(), []byte(prog.PocProg), prog.NOfCalls)
			}
			rnd = rand.New(rand.NewSource(time.Now().UnixNano() + int64(4)*1e12))
			if !prog.ExecutePoCOnly {
				for {
					p := p.Clone()
					p.Mutate(rnd, prog.RecommendedCalls, choiceTable, corpus)
					courier.AppendTestcase(p.Serialize(), []byte(prog.PocProg), prog.NOfCalls)
					time.Sleep(1 * time.Second)
					if flagExtraMutating {
						mgr.doExtraMutate(choiceTable, corpus)
						flagExtraMutating = false
					}
				}
			}
			ch <- 0
			return
		}
	}
	log.Logf(0, "Error occur at parseCustomizedTestcase: %v\n", err)
	return
}

func (mgr *Manager) doExtraMutate(choiceTable *prog.ChoiceTable, corpus []*prog.Prog) {
	log.Logf(0, "doExtraMutate")
	pq := courier.RetrieveFirstArg(courier.Critical)
	if pq != nil {
		testcase := pq.(rpctype.ProgQueue).Prog
		oriP, err := mgr.target.Deserialize(testcase, prog.NonStrict)
		if err != nil {
			return
		}
		rnd := rand.New(rand.NewSource(time.Now().UnixNano() + int64(4)*1e12))
		for i := 1; i < 500; i++ {
			p := oriP.Clone()
			p.Mutate(rnd, prog.RecommendedCalls, choiceTable, corpus)
			courier.AppendTestcase(p.Serialize(), testcase, len(oriP.Calls))
		}
	}
}

func createTemplatePatch(base string) {
	f, err := os.Create(base + "/CorrectTemplate")
	if err != nil {
		log.Logf(0, "Fail to open CorrectTemplate: %v\n", err)
	}
	defer f.Close()
	if prog.MissingSyscall != "" {
		f.Write([]byte("syscall:" + prog.MissingSyscall))
	}
	if prog.LastGroupArg != "" {
		f.Write([]byte("arg:" + prog.LastGroupArg))
	}
}
