package main

import (
	"context"
	"fmt"
	"go_async/async"
	"time"
)

func DoneAsyncInt() int {
	fmt.Println("Warming up ...")
	time.Sleep(3 * time.Second)
	fmt.Println("Done ...")
	return 1
}

func DoneAsyncString() string {
	fmt.Println("Warming up ...")
	time.Sleep(3 * time.Second)
	fmt.Println("Done ...")
	return "Everything is fine!"
}

func main() {
	fmt.Println("Let's start ...")
	futureInt := async.Exec(func() int {
		return DoneAsyncInt()
	})
	fmt.Println("Done is running ...")
	val, _ := futureInt.Await(context.Background())
	fmt.Println(val)

	futureStr := async.Exec(func() string {
		return DoneAsyncString()
	})
	fmt.Println("Done is running ...")
	str, _ := futureStr.Await(context.Background())
	fmt.Println(str)

	// Example with context timeout
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	futureWithContext := async.Exec(func() int {
		return DoneAsyncInt()
	})

	// Await result with context
	resultWithContext, err := futureWithContext.Await(ctx)
	if err != nil {
		fmt.Printf("Context Error: %v\n", err)
	} else {
		fmt.Printf("Result with Context: %d\n", resultWithContext)
	}
}
