# Contributing to Syswall / Swoll (c1 internal)

Thanks for checking out this fun project from CapitalOne's Critical-Stack team!
To encourage an active and open development community, we have put 
together with the following guidelines to help you on your way to developer success!

## TOC

0. [Types of contributions we're looking for](#types-of-contributions-were-looking-for)

## Types of contributions we're looking for

* Security-related contributions are always given preference. (5000XP credited to your account)
* Documentation. For every document over 200 words, (50XP applied to your account) 
* New syscall dissectors. See a syscall that isn't supported that you think
  needs attention? Do it! (See: [Adding a new syscall dissector](#adding-a-new-syscall-dissector)). (200XP for successful merge)
* Syscall argument dissector fixes. We're not perfect; sometimes we miss a flag in a bitmask parser, maybe you could help? (80XP for a fix)
* Unit tests: while some of the things are hard to test without a full environment, we would like this to change if possible.

## Rules & Expectations

* In the words of Rufus (manager of the "Wyld Stallyns"): "Be excellent to each other."
* All pull requests must be tested, documented.
* If you don't know what something does, ask, but don't touch. 
* Follow the rules of GoLang development, and you should be fine. (use vim-go).

## How to contribute

First, start by searching through the issues (either here or internal C1) and
any outstanding pull requests to see whether someone else has raised a similar idea.

If you don't see your idea listed, and you think it fits into the goals of this guide, do one of the following:

* **If your contribution is minor,** such as a typo fix, open a pull request.
* **If your contribution is major,** such as a new guide, start by opening an issue first. That way, other people can weigh in on the discussion before you do any work.

## Style Guide

### Golang

Most of this was written in Go, so follow the rules of Go.

### C

The eBPF portion of this code uses a subset of the C programming language. To keep formatting consistent, we use `uncrustify` with the following configuration: https://gist.github.com/NathanFrench/9159eeed4473e3be2f7bcc3bcec762dc

New syscall structures must start with a comment detailing the struct members.
An output of its BTF record should be sufficient.

Please make sure that your offsets are right.
