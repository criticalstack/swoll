package ross

import (
	"math/rand"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh/terminal"
)

func Paint() string {
	if terminal.IsTerminal(syscall.Stdin) {
		isms := []string{
			"We don't make mistakes, just happy little accidents.",
			"Talent is a pursued interest.",
			"There's nothing wrong with having a tree as a friend.",
			"Let's get crazy.",
			"Believe that you can do it cause you can do it.",
			"On AWS there are no mistakes, only happy little catastrophes",
		}

		rand.Seed(time.Now().Unix())
		return isms[rand.Int()%len(isms)]
	}

	return ""
}
