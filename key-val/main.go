package main

import (
	"errors"
	"fmt"
)

func main() {
	TestUnset()
	TestRollback()
	TestNestedCommit()
	TestTransactionInterleavedKeys()
	TestTransactionRollbackUnset()
	TestTransactionCommitUnset()

	fmt.Println("ALL TESTS PASSED")
}

// sentinel value stored in a transaction layer to record that a key was unset
const deletedSentinel = -1 << 62

// MyData maps keys to values; a special sentinel marks a deleted key
type MyData map[string]int

// txLayer holds the changes made within a single Begin() block.
// If a key maps to deletedSentinel it means Unset was called for that key
// in this layer.
type txLayer struct {
	changes MyData
}

// MyRedis is the concrete implementation of Database.
// All methods use pointer receivers so mutations are visible to callers.
type MyRedis struct {
	data  MyData    // global (committed) storage
	stack []txLayer // open transaction layers, oldest first
}

func (r *MyRedis) Set(key string, value int) {
	if len(r.stack) == 0 {
		r.data[key] = value
	} else {
		r.stack[len(r.stack)-1].changes[key] = value
	}
}

func (r *MyRedis) Get(key string) (int, bool) {
	// Search from the innermost (most recent) transaction layer outward.
	for i := len(r.stack) - 1; i >= 0; i-- {
		if v, ok := r.stack[i].changes[key]; ok {
			if v == deletedSentinel {
				return 0, false // key was unset in this layer
			}
			return v, true
		}
	}
	v, ok := r.data[key]
	return v, ok
}

func (r *MyRedis) Unset(key string) {
	if len(r.stack) == 0 {
		delete(r.data, key)
	} else {
		// Record the deletion in the current transaction layer.
		r.stack[len(r.stack)-1].changes[key] = deletedSentinel
	}
}

func (r *MyRedis) Begin() {
	r.stack = append(r.stack, txLayer{changes: make(MyData)})
}

func (r *MyRedis) Commit() error {
	if len(r.stack) == 0 {
		return errors.New("no open transaction")
	}
	// Merge all layers bottom-to-top into global storage, then clear the stack.
	for _, layer := range r.stack {
		for k, v := range layer.changes {
			if v == deletedSentinel {
				delete(r.data, k)
			} else {
				r.data[k] = v
			}
		}
	}
	r.stack = nil
	return nil
}

func (r *MyRedis) Rollback() error {
	if len(r.stack) == 0 {
		return errors.New("no open transaction")
	}
	// Discard the innermost layer.
	r.stack = r.stack[:len(r.stack)-1]
	return nil
}

func NewDatabase() Database {
	return &MyRedis{data: MyData{}, stack: make([]txLayer, 0)}
}

var _ Database = &MyRedis{}

type Database interface {
	// Set the key to given value
	Set(key string, value int)

	// Get the value for the given key, set 'ok' to true if key exists
	Get(key string) (value int, ok bool)

	// Unset the key, making it just like that key was never set
	Unset(key string)

	// Begin opens a new transaction
	Begin()

	// Commit closes all open transaction blocks, permanently apply the
	// changes made in them.
	Commit() error

	// Rollback undoes all of the commands issued in the most recent
	// transaction block, and closes the block.
	Rollback() error
}

func TestUnset() {
	db := NewDatabase()

	db.Set("ex", 10)
	assertValue(db, "ex", 10)

	db.Unset("ex")
	assertUnset(db, "ex")
	fmt.Println("PASS TestUnset")
}

func TestRollback() {
	db := NewDatabase()

	db.Begin()
	db.Set("a", 10)
	assertValue(db, "a", 10)

	db.Begin()
	db.Set("a", 20)
	assertValue(db, "a", 20)

	err := db.Rollback()
	assertNoError(err)
	assertValue(db, "a", 10)

	err = db.Rollback()
	assertNoError(err)
	assertUnset(db, "a")
	fmt.Println("PASS TestRollback")
}

func TestNestedCommit() {
	db := NewDatabase()

	db.Begin()
	db.Set("a", 30)

	db.Begin()
	db.Set("a", 40)

	err := db.Commit()
	assertNoError(err)

	assertValue(db, "a", 40)

	err = db.Rollback()
	assertError(err)

	err = db.Commit()
	assertError(err)
	fmt.Println("PASS TestNestedCommit")
}

func TestTransactionInterleavedKeys() {
	db := NewDatabase()

	db.Set("a", 10)
	db.Set("b", 10)
	assertValue(db, "a", 10)
	assertValue(db, "b", 10)

	db.Begin()
	db.Set("a", 20)
	assertValue(db, "a", 20)
	assertValue(db, "b", 10)

	db.Begin()
	db.Set("b", 30)
	assertValue(db, "a", 20)
	assertValue(db, "b", 30)

	db.Rollback()
	assertValue(db, "a", 20)
	assertValue(db, "b", 10)

	db.Rollback()
	assertValue(db, "a", 10)
	assertValue(db, "b", 10)
	fmt.Println("PASS TestTransactionInterleavedKeys")
}

func TestTransactionRollbackUnset() {
	db := NewDatabase()

	db.Set("a", 10)
	assertValue(db, "a", 10)

	db.Begin()
	assertValue(db, "a", 10)
	db.Set("a", 20)
	assertValue(db, "a", 20)

	db.Begin()
	db.Unset("a")
	assertUnset(db, "a")

	err := db.Rollback()
	assertNoError(err)
	assertValue(db, "a", 20)

	err = db.Commit()
	assertNoError(err)
	assertValue(db, "a", 20)
	fmt.Println("PASS TestTransactionRollbackUnset")
}

func TestTransactionCommitUnset() {
	db := NewDatabase()

	db.Set("a", 10)
	assertValue(db, "a", 10)

	db.Begin()
	assertValue(db, "a", 10)
	db.Unset("a")
	assertUnset(db, "a")

	err := db.Rollback()
	assertNoError(err)
	assertValue(db, "a", 10)

	db.Begin()
	db.Unset("a")
	assertUnset(db, "a")

	db.Commit()
	assertUnset(db, "a")

	db.Begin()
	assertUnset(db, "a")
	db.Set("a", 20)
	assertValue(db, "a", 20)

	db.Commit()
	assertValue(db, "a", 20)
	fmt.Println("PASS TestTransactionCommitUnset")
}

func assertUnset(db Database, key string) {
	_, ok := db.Get(key)
	if ok {
		panic(fmt.Sprintf("key %q should not exist", key))
	}
}

func assertValue(db Database, key string, value int) {
	v, ok := db.Get(key)
	if !ok || value != v {
		panic(fmt.Sprintf("db.Get(%q) should return %d, true: got %d, %v", key, value, v, ok))
	}
}

func assertNoError(err error) {
	if err != nil {
		panic(fmt.Sprintf("expected no error, got: %v", err))
	}
}

func assertError(err error) {
	if err == nil {
		panic("expected an error, got: nil")
	}
}
