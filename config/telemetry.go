package config

import "time"

type TelemetryConfig struct {
	Enabled        bool              `mapstructure:"enabled" default:"false"`
	ServiceName    string            `mapstructure:"service_name" default:"guardian"`
	ServiceVersion string            `mapstructure:"service_version"`
	Labels         map[string]string `mapstructure:"labels"`
	Exporter       string            `mapstructure:"exporter" default:"stdout"`
	OTLP           struct {
		Headers  map[string]string `mapstructure:"headers"`
		Endpoint string            `mapstructure:"endpoint" default:"otlp.nr-data.net:443"`
	} `mapstructure:"otlp"`
	SamplingFraction int           `mapstructure:"sampling_fraction"`
	MetricInterval   time.Duration `mapstructure:"metric_interval"`
}
