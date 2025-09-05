package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/ethpandaops/breakbear/internal/config"
	"github.com/ethpandaops/breakbear/internal/service"
)

var runCmd = &cobra.Command{
	Use:   "run",
	Short: "Run BreakBear daemon",
	Long:  `Start BreakBear daemon to monitor Docker containers and apply network limits.`,
	RunE:  runBreakBear,
}

func init() {
	rootCmd.AddCommand(runCmd)
}

// runBreakBear is the main daemon logic
func runBreakBear(cmd *cobra.Command, args []string) error {
	logrus.Info("Starting BreakBear daemon")

	// Determine config file path
	configPath := cfgFile
	if configPath == "" {
		configPath = "breakbear.yaml"
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

	// Create and start the BreakBear service
	breakbearService := service.NewService(cfg, logrus.WithField("package", "service"))
	if breakbearService == nil {
		return fmt.Errorf("failed to create BreakBear service")
	}

	logrus.Info("BreakBear daemon started successfully")

	// Start the service
	if err := breakbearService.Start(ctx); err != nil {
		return fmt.Errorf("failed to start BreakBear service: %w", err)
	}

	// Block until context is cancelled (shutdown signal received)
	<-ctx.Done()
	logrus.Info("Shutdown signal received, stopping BreakBear daemon")

	// Gracefully stop the service
	if err := breakbearService.Stop(); err != nil {
		logrus.WithError(err).Error("Error during service shutdown")
		return err
	}

	logrus.Info("BreakBear daemon stopped gracefully")
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
