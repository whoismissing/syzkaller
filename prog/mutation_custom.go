package prog

import (
	"fmt"
	"strings"
)

var NOfCalls = 0
var PocProg string
var ExecutePoCOnly = true
var LastGroupArg = ""
var LastArg = ""
var MissingSyscall = ""

func (ctx *mutator) spliceCus() bool {
	p, r := ctx.p, ctx.r
	if !containPoC(p.Serialize()) {
		return ctx.splice()
	}
	if len(ctx.corpus) == 0 || len(p.Calls)-NOfCalls <= 0 || len(p.Calls) >= ctx.ncalls {
		return false
	}
	p0 := ctx.corpus[r.Intn(len(ctx.corpus))]
	p0c := p0.Clone()
	idx := r.Intn(len(p.Calls)-NOfCalls) + NOfCalls
	p.Calls = append(p.Calls[:idx], append(p0c.Calls, p.Calls[idx:]...)...)
	for i := len(p.Calls) - 1; i >= ctx.ncalls; i-- {
		p.removeCall(i)
	}
	return true
}

// Picks a random complex pointer and squashes its arguments into an ANY.
// Subsequently, if the ANY contains blobs, mutates a random blob.
func (ctx *mutator) squashAnyCus() bool {
	p, r := ctx.p, ctx.r
	if !containPoC(p.Serialize()) {
		return ctx.squashAny()
	}
	complexPtrs := p.complexPtrsCus()
	if len(complexPtrs) == 0 {
		return false
	}
	ptr := complexPtrs[r.Intn(len(complexPtrs))]
	if !p.Target.isAnyPtr(ptr.Type()) {
		p.Target.squashPtr(ptr, true)
	}
	var blobs []*DataArg
	var bases []*PointerArg
	ForeachSubArg(ptr, func(arg Arg, ctx *ArgCtx) {
		if data, ok := arg.(*DataArg); ok && arg.Type().Dir() != DirOut {
			blobs = append(blobs, data)
			bases = append(bases, ctx.Base)
		}
	})
	if len(blobs) == 0 {
		return false
	}
	// TODO(dvyukov): we probably want special mutation for ANY.
	// E.g. merging adjacent ANYBLOBs (we don't create them,
	// but they can appear in future); or replacing ANYRES
	// with a blob (and merging it with adjacent blobs).
	idx := r.Intn(len(blobs))
	arg := blobs[idx]
	base := bases[idx]
	baseSize := base.Res.Size()
	arg.data = mutateData(r, arg.Data(), 0, maxBlobLen)
	// Update base pointer if size has increased.
	if baseSize < base.Res.Size() {
		s := analyze(ctx.ct, ctx.corpus, p, p.Calls[0])
		newArg := r.allocAddr(s, base.Type(), base.Res.Size(), base.Res)
		*base = *newArg
	}
	return true
}

func (ctx *mutator) insertCallAtEnd() bool {
	p, r := ctx.p, ctx.r
	if !containPoC(p.Serialize()) {
		return true
	}
	if len(p.Calls) >= ctx.ncalls {
		return false
	}
	idx := len(p.Calls)
	var c *Call
	if idx < len(p.Calls) {
		c = p.Calls[idx]
	}
	s := analyze(ctx.ct, ctx.corpus, p, c)
	calls := r.generateCall(s, p, idx)
	p.insertBefore(c, calls)
	for len(p.Calls) > ctx.ncalls {
		p.removeCall(idx)
	}
	return true
}

func (ctx *mutator) insertCallCus() bool {
	p, r := ctx.p, ctx.r
	if !containPoC(p.Serialize()) {
		return ctx.insertCall()
	}
	if len(p.Calls) >= ctx.ncalls {
		return false
	}
	idx := r.biasedRand(len(p.Calls)+1-NOfCalls, 5) + NOfCalls

	if NOfCalls == len(p.Calls) {
		idx = len(p.Calls)
	}
	var c *Call
	if idx < len(p.Calls) {
		c = p.Calls[idx]
	}
	s := analyze(ctx.ct, ctx.corpus, p, c)
	calls := r.generateCall(s, p, idx)
	p.insertBefore(c, calls)
	for len(p.Calls) > ctx.ncalls {
		p.removeCall(idx)
	}
	return true
}

// Removes a random call from program.
func (ctx *mutator) removeCallCus() bool {
	p, r := ctx.p, ctx.r
	if !containPoC(p.Serialize()) {
		return ctx.removeCall()
	}
	if len(p.Calls) == 0 {
		return false
	}
	idx := r.Intn(len(p.Calls)-NOfCalls) + NOfCalls
	p.removeCall(idx)
	return true
}

// Mutate an argument of a random call.
func (ctx *mutator) mutateArgCus() bool {
	start := NOfCalls
	p, r := ctx.p, ctx.r
	if !containPoC(p.Serialize()) {
		return ctx.mutateArg()
	}
	if len(p.Calls) == 0 {
		return false
	}
	idx := chooseCallCus(p, r, start)
	if idx < 0 {
		return false
	}
	c := p.Calls[idx]
	updateSizes := true
	for stop, ok := false, false; !stop; stop = ok && r.oneOf(3) {
		ok = true
		ma := &mutationArgs{target: p.Target}
		ForeachArg(c, ma.collectArg)
		if len(ma.args) == 0 {
			return false
		}
		s := analyze(ctx.ct, ctx.corpus, p, c)
		chosenIdx := randomChoice(ma.priorities, r)
		arg, argCtx := ma.args[chosenIdx], ma.ctxes[chosenIdx]
		calls, ok1 := p.Target.mutateArg(r, s, arg, argCtx, &updateSizes)
		if !ok1 {
			ok = false
			continue
		}
		p.insertBefore(c, calls)
		idx += len(calls)
		for len(p.Calls) > ctx.ncalls {
			idx--
			p.removeCall(idx)
		}
		if idx < 0 || idx >= len(p.Calls) || p.Calls[idx] != c {
			panic(fmt.Sprintf("wrong call index: idx=%v calls=%v p.Calls=%v ncalls=%v",
				idx, len(calls), len(p.Calls), ctx.ncalls))
		}
		if updateSizes {
			p.Target.assignSizesCall(c)
		}
	}
	return true
}

// Select a call based on the complexity of the arguments.
func chooseCallCus(p *Prog, r *randGen, start int) int {
	var callPriorities []float64
	noArgs := true

	for i, c := range p.Calls {
		if i < start {
			continue
		}
		totalPrio := float64(0)
		ForeachArg(c, func(arg Arg, ctx *ArgCtx) {
			prio, stopRecursion := arg.Type().getMutationPrio(p.Target, arg, false)
			totalPrio += prio
			ctx.Stop = stopRecursion
		})
		callPriorities = append(callPriorities, totalPrio)
		if len(c.Args) > 0 {
			noArgs = false
		}
	}

	// Calls without arguments.
	if noArgs {
		return -1
	}
	return start + randomChoice(callPriorities, r)
}

func (p *Prog) complexPtrsCus() (res []*PointerArg) {
	for i, c := range p.Calls {
		if i < NOfCalls {
			continue
		}
		ForeachArg(c, func(arg Arg, ctx *ArgCtx) {
			if ptrArg, ok := arg.(*PointerArg); ok && p.Target.isComplexPtr(ptrArg) {
				res = append(res, ptrArg)
				ctx.Stop = true
			}
		})
	}
	return
}

func containPoC(prog []byte) bool {
	if !ExecutePoCOnly {
		return false
	}
	sProg := string(prog)
	if len(sProg) < len(PocProg) {
		return false
	}

	if strings.Compare(PocProg, sProg[:len(PocProg)]) == 0 {
		return true
	}
	return false
}
