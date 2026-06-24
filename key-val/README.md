# key-val

A simple in-memory key-value store implemented in Go, with support for nested transactions.

## Features

- **Set / Get / Unset** — basic key-value operations on string keys and integer values
- **Nested transactions** — open multiple transaction blocks with `Begin()`; each one is independent and can be rolled back or committed individually
- **Rollback** — discards all changes made in the most recent open transaction block
- **Commit** — applies all open transaction blocks to the global store at once

## Usage

```go
db := NewDatabase()

db.Set("a", 10)
v, ok := db.Get("a") // 10, true
db.Unset("a")

// Transactions
db.Begin()
db.Set("a", 20)

db.Begin()          // nested transaction
db.Set("a", 30)
db.Rollback()       // discard inner block → "a" is back to 20

db.Commit()         // apply outer block → "a" = 20 in global store
```

## Interface

```go
type Database interface {
    Set(key string, value int)
    Get(key string) (value int, ok bool)
    Unset(key string)
    Begin()
    Commit() error
    Rollback() error
}
```

`Commit` and `Rollback` return an error when there is no open transaction.

## Running

```bash
go run main.go
```

This executes the built-in test suite and prints `ALL TESTS PASSED` on success.
