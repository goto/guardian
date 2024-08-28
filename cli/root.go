package cli

import (
	"context"

	"github.com/MakeNowJust/heredoc"
	handlerv1beta1 "github.com/goto/guardian/api/handler/v1beta1"
	"github.com/goto/guardian/pkg/opentelemetry"
	"github.com/goto/salt/cmdx"
	"github.com/spf13/cobra"
)

func New(cfg *Config) *cobra.Command {
	cliConfig = cfg
	var shutdown func()
	var cmd = &cobra.Command{
		Use:   "guardian <command> <subcommand> [flags]",
		Short: "Universal data access control",
		Long: heredoc.Doc(`
			Universal access control to cloud apps and infrastructure.`),
		SilenceUsage:  true,
		SilenceErrors: true,
		Annotations: map[string]string{
			"group": "core",
			"help:learn": heredoc.Doc(`
				Use 'guardian <command> --help' for info about a command.
				Read the manual at https://goto.github.io/guardian/
			`),
			"help:feedback": heredoc.Doc(`
				Open an issue here https://github.com/goto/guardian/issues
			`),
		},
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			// initialize tracing
			ctx := context.Background()
			var shutdownOtel func() error = func() error { return nil }
			if cliConfig.Telemetry.Enabled {
				var err error
				shutdownOtel, err = opentelemetry.Init(ctx, opentelemetry.Config{
					ServiceName:      cfg.Telemetry.ServiceName,
					ServiceVersion:   cfg.Telemetry.ServiceVersion,
					SamplingFraction: cfg.Telemetry.SamplingFraction,
					MetricInterval:   cfg.Telemetry.MetricInterval,
					CollectorAddr:    cfg.Telemetry.OTLP.Endpoint,
				})
				if err != nil {
					return nil
				}
			}

			defer shutdownOtel()
			return nil
		},
		PersistentPostRun: func(cmd *cobra.Command, args []string) {
			// shutdown tracing
			shutdown()
		},
	}

	protoAdapter := handlerv1beta1.NewAdapter()
	cmd.AddCommand(ResourceCmd(protoAdapter))
	cmd.AddCommand(ProviderCmd(protoAdapter))
	cmd.AddCommand(PolicyCmd(protoAdapter))
	cmd.AddCommand(appealsCommand())
	cmd.AddCommand(grantsCommand(protoAdapter))
	cmd.AddCommand(ServerCommand())
	cmd.AddCommand(JobCmd())
	cmd.AddCommand(configCommand())
	cmd.AddCommand(VersionCmd())

	// Help topics
	cmdx.SetHelp(cmd)
	cmd.AddCommand(cmdx.SetCompletionCmd("guardian"))
	cmd.AddCommand(cmdx.SetHelpTopicCmd("environment", envHelp))
	cmd.AddCommand(cmdx.SetRefCmd(cmd))

	return cmd
}
