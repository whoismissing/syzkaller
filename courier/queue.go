package courier

import (
	"sync"

	"github.com/google/syzkaller/pkg/rpctype"
)

const (
	Mutating = 0
	Commands = 1
	S2E      = 2
	Critical = 3
)

type S2EArgs struct {
	Prog    []byte
	Pointer []byte
}

var MutateArgsQueue = make([]rpctype.ProgQueue, 0)
var CriticalPoCQueue = make([]rpctype.ProgQueue, 0)

var CommandsQueue = make([]string, 0)
var S2EArgsQueue = make([]S2EArgs, 0)
var Mutex = &sync.Mutex{}

//Append testcase to a queue waits for mutating
func AppendMutatingQueue(p, pocProg []byte, nOfCalls int) {
	a := rpctype.ProgQueue{
		Prog:     p,
		NOfCalls: nOfCalls,
		PocProg:  pocProg,
	}
	MutateArgsQueue = append(MutateArgsQueue, a)
}

func AppendCriticalPoCQueue(p []byte) {
	a := rpctype.ProgQueue{
		Prog:     p,
		NOfCalls: 0,
		PocProg:  p,
	}
	CriticalPoCQueue = append(CriticalPoCQueue, a)
}

func AppendCommandsQueue(p []byte) {
	CommandsQueue = append(CommandsQueue, string(p))
}

func AppendS2EQueue(p S2EArgs) {
	S2EArgsQueue = append(S2EArgsQueue, p)
}

func RetrieveFirstArg(flag int) interface{} {
	switch flag {
	case Mutating:
		if len(MutateArgsQueue) == 0 {
			break
		}
		p := MutateArgsQueue[0]
		MutateArgsQueue = MutateArgsQueue[1:]
		return p
	case Commands:
		if len(CommandsQueue) == 0 {
			break
		}
		p := CommandsQueue[0]
		CommandsQueue = CommandsQueue[1:]
		return []byte(p)
	case S2E:
		if len(S2EArgsQueue) == 0 {
			break
		}
		p := S2EArgsQueue[0]
		S2EArgsQueue = S2EArgsQueue[1:]
		return p
	}
	return nil
}
