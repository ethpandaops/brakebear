package main

import (
	"os"

	"github.com/ethpandaops/breakbear/internal/cmd"
	"github.com/sirupsen/logrus"
)

func main() {
	if err := cmd.Execute(); err != nil {
		logrus.WithError(err).Fatal("Failed to execute command")
		os.Exit(1)
	}
}
