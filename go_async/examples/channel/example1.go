package main

import (
	"fmt"
	"time"
)

func worker(id int, ch chan<- string) {
	time.Sleep(time.Second)
	ch <- fmt.Sprintf("Worker %d done", id)
}

func DoneAsync() chan int {
	r := make(chan int)
	fmt.Println("Warming up ...")
	go func() {
		time.Sleep(3 * time.Second)
		r <- 1
		fmt.Println("Done ...")
	}()
	return r
}

func main() {
	ch := make(chan string)
	for i := 1; i <= 5; i++ {
		go worker(i, ch)
	}

	for i := 1; i <= 5; i++ {
		fmt.Println(<-ch)
	}

	// another perspective
	fmt.Println("Let's start ...")
	val := DoneAsync()
	fmt.Println("Done is running ...")
	fmt.Println(<-val)
}
