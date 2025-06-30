package utils

import (
	"bytes"
	"fmt"
	"log"
	"os"
)

// GetEnv retrieves the value of the environment variable named by the key.
// If the environment variable is not present, it returns the overrideValue.
// Params:
// - key: string - the name of the environment variable
// - overrideValue: string - the value to return if the environment variable is not present
// Returns:
// - string: the value of the environment variable or the overrideValue
// - error: error if the environment variable is not present and overrideValue is empty
func GetEnv(key string, overrideValue string) (string, error) {
	if overrideValue != "" {
		return overrideValue, nil
	}

	val := os.Getenv(key)
	if val == "" {
		return overrideValue, fmt.Errorf("err: failed to get env var for key: %v", key)
	}

	return val, nil
}

// NewTestLogger creates a new logger that writes to the provided buffer.
// Params:
// - buf: *bytes.Buffer - the buffer to write logs to
// Returns:
// - *log.Logger: the created logger
func NewTestLogger(buf *bytes.Buffer) *log.Logger {
	return log.New(buf, "TEST: ", log.LstdFlags) // Logs are written to buffer
}
