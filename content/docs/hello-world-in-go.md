+++
title = "Hello world in golang"
description = "Hello world in golang"
date = 2020-11-19T17:47:31+05:30
weight = 20
draft = false
bref = "Hello world!, now let's Go"
toc = true
+++
## Introduction
[Go](https://golang.org) is an open source programming language that makes
it easy to build **simple**, **reliable**, and **efficient** software.

## How to write readable enums
Not the most idiomatic way, but gets the job done !
```go
package main

import (
    "fmt"
)

type Action struct {
    val  uint32
    repr string
}

func (a *Action) Val() uint32 {
    return a.val
}

func (a *Action) String() string {
    return a.repr
}

var (
    Read  = Action{0, "Read"}
    Write = Action{1, "Write"}
    Attr  = Action{2, "Attr"}
)

func main() {
    fmt.Println("%s: %d", Read, Read.Val())
}
```
