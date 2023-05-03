package cli

import (
	"context"
	"fmt"

	"github.com/MakeNowJust/heredoc"
	"github.com/go-playground/validator/v10"
	"github.com/goto/guardian/internal/server"
	"github.com/goto/guardian/jobs"
	"github.com/goto/guardian/pkg/crypto"
	"github.com/goto/guardian/plugins/notifiers"
	"github.com/goto/salt/log"
	"github.com/spf13/cobra"
)

func JobCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "job",
		Aliases: []string{"jobs"},
		Short:   "Manage jobs",
		Example: heredoc.Doc(`
			$ guardian job run fetch_resources
		`),
	}

	cmd.AddCommand(
		runJobCmd(),
	)

	cmd.PersistentFlags().StringP("config", "c", "./config.yaml", "Config file path")
	cmd.MarkPersistentFlagFilename("config")

	return cmd
}

func runJobCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "run",
		Short: "Fire a specific job",
		Example: heredoc.Doc(`
			$ guardian job run fetch_resources
			$ guardian job run grant_expiration_reminder
			$ guardian job run grant_expiration_revocation
		`),
		Args: cobra.ExactValidArgs(1),
		ValidArgs: []string{
			string(jobs.FetchResources),
			string(jobs.ExpiringGrantNotification),
			string(jobs.RevokeExpiredGrants),
			string(jobs.RevokeGrantsByUserCriteria),

			string(jobs.RevokeExpiredAccess),
			string(jobs.ExpiringAccessNotification),
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			configFile, err := cmd.Flags().GetString("config")
			if err != nil {
				return fmt.Errorf("getting config flag value: %w", err)
			}
			config, err := server.LoadConfig(configFile)
			if err != nil {
				return fmt.Errorf("loading config: %w", err)
			}

			logger := log.NewLogrus(log.LogrusWithLevel(config.LogLevel))
			crypto := crypto.NewAES(config.EncryptionSecretKeyKey)
			validator := validator.New()
			notifier, err := notifiers.NewClient(&config.Notifier)
			if err != nil {
				return err
			}

			services, err := server.InitServices(server.ServiceDeps{
				Config:    &config,
				Logger:    logger,
				Validator: validator,
				Notifier:  notifier,
				Crypto:    crypto,
			})
			if err != nil {
				return fmt.Errorf("initializing services: %w", err)
			}

			handler := jobs.NewHandler(
				logger,
				services.GrantService,
				services.ProviderService,
				notifier,
				crypto,
				validator,
			)

			jobsMap := map[jobs.Type]func(context.Context, jobs.Config) error{
				jobs.FetchResources:             handler.FetchResources,
				jobs.ExpiringGrantNotification:  handler.GrantExpirationReminder,
				jobs.RevokeExpiredGrants:        handler.RevokeExpiredGrants,
				jobs.RevokeGrantsByUserCriteria: handler.RevokeGrantsByUserCriteria,

				// deprecated job names
				jobs.ExpiringAccessNotification: handler.GrantExpirationReminder,
				jobs.RevokeExpiredAccess:        handler.RevokeExpiredGrants,
			}

			jobName := jobs.Type(args[0])
			job := jobsMap[jobName]
			if job == nil {
				return fmt.Errorf("invalid job name: %s", jobName)
			}
			jobConfig := config.Jobs[jobName].Config
			if err := job(context.Background(), jobConfig); err != nil {
				return fmt.Errorf(`failed to run job "%s": %w`, jobName, err)
			}

			return nil
		},
	}

	return cmd
}
