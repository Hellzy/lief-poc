package main

import (
	"fmt"
	"math/rand"
)

//go:noinline
func Int() int {
	return 4
}

func main() {
	_ = Int() // Make sure compiler doesn't optimise out unused funcs
	fmt.Println(rand.Int())
}
