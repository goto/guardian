package opentelemetry

import "time"

type Config struct {
	Enabled        bool              `mapstructure:"enabled" default:"false"`
	ServiceName    string            `mapstructure:"service_name" default:"guardian"`
	ServiceVersion string            `mapstructure:"service_version"`
	Labels         map[string]string `mapstructure:"labels"`
	Exporter       string            `mapstructure:"exporter" default:"stdout"`
	OTLP           struct {
		Headers  map[string]string `mapstructure:"headers"`
		Endpoint string            `mapstructure:"endpoint" default:"127.0.0.1:4317"`
	} `mapstructure:"otlp"`
	SamplingFraction int           `mapstructure:"sampling_fraction"`
	MetricInterval   time.Duration `mapstructure:"metric_interval" default:"15s"`
}
