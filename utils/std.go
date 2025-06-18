package utils

import (
	"fmt"
	"log/slog"
	"os"
)

func Fatal(err error) {
	slog.Error(err.Error())
	_, _ = fmt.Fprintln(os.Stderr, "================================================")
	_, _ = fmt.Fprintln(os.Stderr, "Fatal error:")
	_, _ = fmt.Fprintln(os.Stderr, err.Error())
	os.Exit(1)
}
