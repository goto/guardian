package cli

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/goto/guardian/pkg/log"
	"github.com/mitchellh/mapstructure"

	"github.com/MakeNowJust/heredoc"
	"github.com/go-playground/validator/v10"
	"github.com/goto/guardian/internal/server"
	"github.com/goto/guardian/jobs"
	"github.com/goto/guardian/pkg/crypto"
	"github.com/goto/guardian/plugins/notifiers"
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
			$ guardian job run expiring_grant_notification
			$ guardian job run revoke_expired_grants
			$ guardian job run revoke_grants_by_user_criteria
			$ guardian job run grant_dormancy_check
			$ guardian job run pending_approvals_reminder
		`),
		Args: cobra.ExactValidArgs(1),
		ValidArgs: []string{
			string(jobs.TypeFetchResources),
			string(jobs.TypeExpiringGrantNotification),
			string(jobs.TypeRevokeExpiredGrants),
			string(jobs.TypeRevokeGrantsByUserCriteria),
			string(jobs.TypeGrantDormancyCheck),
			string(jobs.TypePendingApprovalsReminder),
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

			logger := log.NewCtxLogger(config.LogLevel, []string{config.AuditLogTraceIDHeaderKey})
			crypto := crypto.NewAES(config.EncryptionSecretKeyKey)
			validator := validator.New()
			var notifierMap map[string]interface{}
			errr := json.Unmarshal([]byte(config.Notifiers), &notifierMap)
			if errr != nil {
				fmt.Println(errr)
			}
			var notifierConfigMap map[string]notifiers.Config
			err = mapstructure.Decode(notifierMap, &notifierConfigMap)
			if err != nil {
				fmt.Println(err)

			}
			notifierConfig := []notifiers.Config{}
			if config.Notifiers != "" {
				for _, val := range notifierConfigMap {
					notifierConfig = append(notifierConfig, val)

				}
			} else {
				// map old to the new format
				oldConfig := config.Notifier
				oldConfig.Criteria = "true"
				notifierConfig = append(notifierConfig, oldConfig)
			}
			notifier, err := notifiers.NewMultiClient(&notifierConfig, logger)
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
				services.ReportService,
				services.ProviderService,
				notifier,
				crypto,
				validator,
			)

			jobsMap := map[jobs.Type]*struct {
				handler func(context.Context, jobs.Config) error
				config  jobs.Config
			}{
				jobs.TypeFetchResources: {
					handler: handler.FetchResources,
					config:  config.Jobs.FetchResources.Config,
				},
				jobs.TypeExpiringGrantNotification: {
					handler: handler.GrantExpirationReminder,
					config:  config.Jobs.ExpiringGrantNotification.Config,
				},
				jobs.TypeRevokeExpiredGrants: {
					handler: handler.RevokeExpiredGrants,
					config:  config.Jobs.RevokeExpiredGrants.Config,
				},
				jobs.TypeRevokeGrantsByUserCriteria: {
					handler: handler.RevokeGrantsByUserCriteria,
					config:  config.Jobs.RevokeGrantsByUserCriteria.Config,
				},
				jobs.TypeGrantDormancyCheck: {
					handler: handler.GrantDormancyCheck,
					config:  config.Jobs.GrantDormancyCheck.Config,
				},
				jobs.TypePendingApprovalsReminder: {
					handler: handler.PendingApprovalsReminder,
					config:  config.Jobs.PendingApprovalsReminder.Config,
				},
			}

			jobName := jobs.Type(args[0])
			job := jobsMap[jobName]
			if job == nil {
				return fmt.Errorf("invalid job name: %s", jobName)
			}
			if err := job.handler(context.Background(), job.config); err != nil {
				return fmt.Errorf(`failed to run job "%s": %w`, jobName, err)
			}

			return nil
		},
	}

	return cmd
}
