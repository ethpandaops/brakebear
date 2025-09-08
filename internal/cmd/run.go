package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/ethpandaops/brakebear/internal/config"
	"github.com/ethpandaops/brakebear/internal/service"
)

var runCmd = &cobra.Command{ //nolint:gochecknoglobals
	Use:   "run",
	Short: "Run BrakeBear daemon",
	Long:  `Start BrakeBear daemon to monitor Docker containers and apply network limits.`,
	RunE:  runBrakeBear,
}

func init() { //nolint:gochecknoinits
	rootCmd.AddCommand(runCmd)
}

// runBrakeBear is the main daemon logic
func runBrakeBear(cmd *cobra.Command, args []string) error {
	logrus.Info("Starting BrakeBear daemon")

	// Determine config file path
	configPath := cfgFile
	if configPath == "" {
		configPath = "brakebear.yaml"
	}

	// Load configuration
	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		return fmt.Errorf("failed to load configuration: %w", err)
	}

	logrus.WithFields(logrus.Fields{
		"log_level":       cfg.LogLevel,
		"container_count": len(cfg.DockerContainers),
	}).Info("Configuration loaded")

	// Create context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle signals for graceful shutdown
	go handleSignals(cancel)

	// Create and start the BrakeBear service
	brakebearService := service.NewService(cfg, logrus.WithField("package", "service"))
	if brakebearService == nil {
		return errors.New("failed to create BrakeBear service")
	}

	logrus.Info("BrakeBear daemon started successfully")

	// Start the service
	if err := brakebearService.Start(ctx); err != nil {
		return fmt.Errorf("failed to start BrakeBear service: %w", err)
	}

	// Block until context is cancelled (shutdown signal received)
	<-ctx.Done()
	logrus.Info("Shutdown signal received, stopping BrakeBear daemon")

	// Gracefully stop the service
	if err := brakebearService.Stop(); err != nil {
		logrus.WithError(err).Error("Error during service shutdown")
		return fmt.Errorf("failed to stop BrakeBear service: %w", err)
	}

	logrus.Info("BrakeBear daemon stopped gracefully")
	return nil
}

// handleSignals handles OS signals for graceful shutdown
func handleSignals(cancel context.CancelFunc) {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	sig := <-sigCh
	logrus.WithField("signal", sig.String()).Info("Received shutdown signal")

	// Cancel the context to trigger graceful shutdown
	cancel()
}
