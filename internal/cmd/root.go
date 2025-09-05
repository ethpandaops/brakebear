package cmd

import (
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	cfgFile  string
	logLevel string
	rootCmd  = &cobra.Command{
		Use:   "breakbear",
		Short: "Docker container network bandwidth limiter",
		Long:  `BreakBear applies network bandwidth limits, latency, jitter, and packet loss to Docker containers using netns and tc.`,
	}
)

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() error {
	return rootCmd.Execute()
}

func init() {
	cobra.OnInitialize(initConfig)

	// Global flags
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is breakbear.yaml)")
	rootCmd.PersistentFlags().StringVar(&logLevel, "log-level", "info", "log level (debug, info, warn, error)")

	// Setup logging
	cobra.OnInitialize(setupLogging)
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	if cfgFile != "" {
		// Use config file from the flag.
		viper.SetConfigFile(cfgFile)
	} else {
		// Search config in current directory with name "breakbear" (without extension).
		viper.AddConfigPath(".")
		viper.SetConfigType("yaml")
		viper.SetConfigName("breakbear")
	}

	viper.AutomaticEnv() // read in environment variables that match

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		logrus.WithField("config", viper.ConfigFileUsed()).Info("Using config file")
	} else {
		if cfgFile != "" {
			// Config file was explicitly specified but couldn't be read
			logrus.WithError(err).WithField("config", cfgFile).Warn("Unable to read config file")
		} else {
			// No config file found, that's okay - we'll use defaults
			logrus.Debug("No config file found, using defaults")
		}
	}
}

// setupLogging configures logrus based on the log level flag
func setupLogging() {
	level, err := logrus.ParseLevel(logLevel)
	if err != nil {
		logrus.WithError(err).WithField("level", logLevel).Warn("Invalid log level, using info")
		level = logrus.InfoLevel
	}

	logrus.SetLevel(level)
	logrus.SetFormatter(&logrus.TextFormatter{
		FullTimestamp: true,
	})

	logrus.WithFields(logrus.Fields{
		"level":  level.String(),
		"config": getConfigFile(),
	}).Info("BreakBear starting up")
}

// getConfigFile returns the config file being used or default
func getConfigFile() string {
	if cfgFile != "" {
		return cfgFile
	}
	if viper.ConfigFileUsed() != "" {
		return viper.ConfigFileUsed()
	}
	return "breakbear.yaml (default)"
}
