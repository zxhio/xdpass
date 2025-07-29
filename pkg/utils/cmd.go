package utils

import (
	"context"
	"os/exec"
	"time"
)

func RunCommandWithContext(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.CombinedOutput()
	// we don't treat timeout as error
	if err != nil && ctx.Err() != context.DeadlineExceeded {
		if _, ok := err.(*exec.ExitError); ok {
			return out, err
		}
		return nil, err
	}
	return out, nil
}

func RunCommandWithTimeout(timeout time.Duration, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return RunCommandWithContext(ctx, name, args...)
}

func RunCommand(name string, args ...string) ([]byte, error) {
	return RunCommandWithContext(context.Background(), name, args...)
}
