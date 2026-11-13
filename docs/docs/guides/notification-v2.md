# Lark notification v2

The optional `lark_v2` provider delegates notification delivery to guardian-notification-worker.
The worker sends all ten Guardian notification types through two Lark applications: pending
approval cards/reminders and access-status notifications. Only the pending app consumes card
callbacks. Approval decisions use Guardian's existing internal API and authenticated user header.

```json
{
  "lark_v2": {
    "provider": "lark_v2",
    "criteria": "false",
    "worker_url": "http://notification-worker.example.com:8080",
    "timeout_seconds": 30
  }
}
```

Use the existing NOTIFIERS configuration mechanism. The worker URL is an origin without a path;
the adapter appends `/v1/notifications`. Worker HTTP caller access is controlled by the internal
network/proxy boundary. Guardian needs no worker token or Lark app credentials for this provider. Timeout defaults
to 30 seconds and must be between 5 and 120 seconds.

The adapter sends a structured event with a stable ID across up to three transient attempts,
individual recipient, type, variables, labels and optional exact approval context. Permanent 4xx
failures are not retried; 429/5xx and unconfirmed transport responses are bounded by the timeout.
Returned errors omit request URLs, recipients, tokens and response bodies. Notifications remain
best effort and do not roll back an appeal when delivery fails.

Grant notifications link to their appeal when one exists. Otherwise the worker links to the
known package or the Console access resources page, never the Console homepage. Dormant-access
digests preserve safe per-entry appeal/package identifiers for individual links. Hosts come from
the worker's configured Console origin. Imported grants do not acquire fabricated appeal IDs.

Scheduled resource fetching logs and skips individual provider failures, including stale provider
configuration, and continues with the remaining providers. Failure to enumerate providers or a
canceled execution still fails the job. Direct API callers retain the partial-sync error. Dormancy
checks skip unsupported activity providers and log genuine provider failures. Reminder and bot-expiry
delivery failures are logged per recipient/team and do not stop the remaining batch. Skipping an error
does not imply that access was successfully changed or that a notification was delivered.

Guardian suppresses separate routine user notifications for identified package implementation
grants: CloudSSO group membership and bot STS trust under `package_user`, plus resource copies
under `package_access_bot_ram_role` and `package_access_bot_ram_user`. Classification requires
package linkage and the matching account/resource type, including children with their own appeal.
The actual Guardian package membership and root package resource access remain visible.
Expiry, revocation, owner-change, dormant-access digests, and child appeal outcome notifications
use this rule before delivery, so it applies to legacy notifiers as well as v2. Suppression is logged
with the grant/appeal identifier and reason. Actual access changes and audit records still execute.
Pending manual approvals and explicit comments remain visible; Siren bot-expiry alerts are separate
and unchanged. Unknown/unlinked grants and imported direct access are not hidden simply because
they lack an appeal. No extra table, lookup, or dependency on the worker is introduced.

MaxCompute project-member prerequisites are normally permanent and therefore outside expiry
reminders. Ungrouped prerequisites cannot reliably be distinguished from legacy/imported access
with current persisted provenance, so this filter does not guess. Functional-role package setup
grants are likewise not classified as technical children merely because they use a package account.

Approval notifications identify the persisted appeal ID, approval IDs and revision. Guardian
selects recipients from pending manual steps and excludes stale revisions. The v2 adapter groups the
batch by recipient, appeal and revision into one card listing all that person's pending steps.
Legacy v1/Slack links keep their individual step names.

After approval commits, Guardian notifies newly eligible recipients with all their current pending
steps. Resolving another parallel step does not resend unchanged pending notifications. Adding an
approver to a blocked step sends no card until the step becomes pending. Approve all acts only on
the displayed IDs; consecutive future steps may be included explicitly and processed after Guardian unlocks them. If a later step
call fails, previously committed approvals remain and the worker stops with an explicit partial/
unconfirmed result. No batch transaction or automatic mutation retry is introduced.

Approval context also covers newly added approvers on pending steps. The worker verifies the authenticated Lark operator and current
Guardian state; it cannot replace Guardian's eligibility or self-approval checks. Direct approval-ID
actions reject obsolete/stale revisions before provider work and again inside the locked commit.
Existing protobuf methods are unchanged. Migration 000036 adds notification_card_receipts to
Guardian's existing database for durable pending-card delivery/refresh metadata.

The worker calls `POST /api/v1beta1/appeals/{appeal_id}/approvals/{approval_id}` with the verified
person's identity through Guardian's configured trusted internal header. Keep this route private.
The worker does not mint OIDC user tokens. Reject requires a reason in the worker card; existing
API callers retain their current reason rules. Rejection notifications include the submitted reason.

Keep v2 disabled until its integration pilot passes. v1 and v2 entries are independently configurable;
enabling both for the same recipients produces duplicate versions. Cutover explicitly disables v1
Lark delivery and enables v2, with no automatic fallback after an uncertain delivery. Existing v1
custom JSON message templates apply to v1; v2 card rendering belongs to the worker.

The worker has one replica with Recreate deployment and no database. Guardian's server stores
pending-card receipts before delivery, confirms Lark message IDs, and reconciles changed card
state with the worker's private POST /v1/cards/refresh endpoint. This updates other approvers'
cards after Lark or console/API decisions, cancellations and revision changes. Reconciliation
survives restarts, uses DB leases across Guardian processes, and does not rewrite unchanged cards.
Pending delivery recovery reuses the saved event ID for up to 55 minutes, within Lark's one-hour
idempotency window. Other notification types remain best effort; there is no nudge scheduler.

Apply migration 000036 through the established Guardian migration workflow before enabling this
server's v2 configuration. Startup checks the required table for v2; legacy-only servers continue
without it. Deploy the worker's refresh endpoint before the new Guardian server. Receipt metadata
contains no bot/API credentials, notification body or rejection text. Cards stay tracked until
terminal appeal state or revision replacement. Normal updates take a few seconds under light
load and retry on failures or busy callbacks; stale clicks are always checked against Guardian.

The UUID fix uses 43-character base64url SHA-256 values, retaining stable retry keys within Lark's
50-character maximum. The notifier manager now filters each recipient before provider grouping.
The completion-race fix aborts a locked update that unexpectedly becomes terminal without a
prepared grant, then safely retries from a fresh snapshot. Retries are bounded and pinned to the
original appeal revision and exact step; provider work remains outside DB transactions. No
Approved state can be committed through that path before the necessary grant work is prepared.
An uncertain worker approval is read back rather than automatically retried.

Card action integrity now uses persisted receipts rather than a worker signing key. The worker
reads GET /api/v1beta1/notification-cards/{message_id} through Guardian's existing configured
authentication. The endpoint only returns the authenticated recipient's message/appeal/revision,
covered step IDs and closed status. The worker refuses unknown/mismatched/closed receipts and
never expands the original covered steps. Callback app/operator and live email checks remain.
The existing notification_card_receipts table is reused without another migration. Rebuild both
images and update their deployment pins; previously supplied images still require the retired keys.


V2 card presentation now uses explicit resource_id/resource_display_name/resource_urn and
resource/provider types, keeping the legacy resource_name field compatible. The worker uses the
environment's CONSOLE_BASE_URL for request and package routes. The v2 adapter filters arbitrary
private policy/HR fields before delivery, including recovery; only the user-facing access reason
is extracted from policy questions. Notification criteria still run before presentation filtering.

The shared v5 card fingerprint triggers a one-time repaint of active tracked cards on this UI
upgrade. Later unchanged checks preserve forms as before; the upgrade itself can reset an open
rejection form. Closed historical receipts are not reopened. Rebuild/deploy compatible Guardian
and worker images together; no additional database migration is needed.

Notification changes are compared against the appeal snapshot under the approval commit lock,
so an approver added by a concurrent operation is not notified again from an older snapshot.
Cancellation also revalidates status and revision under this lock. It cannot overwrite a final
approval already committed or cancel a replacement revision based on an old read.

These guards do not make external provider operations atomic with the database. GrantAccess still
runs before the locked approval commit. If a cancellation/rejection/edit wins while provider work
is in flight, access may already have changed upstream even though the approval commit is refused.
Resolving that existing race requires durable coordination of provider work and request transitions;
blind compensation can revoke access granted by another winning operation. This limitation is
separate from card receipts and must not be represented as exactly-once provisioning.

Stage continuity: lark_v2 Ensure serializes per worker origin/appeal/revision/normalized recipient
using a transaction-scoped PostgreSQL advisory lock, including the no-existing-row case. The first
notification prepares/sends a message; later eligible IDs extend the earliest saved receipt and
schedule reconciliation. Changed scope clears the state hash and fences older reconciliation
leases. Repeated identical notifications preserve forms. Existing created_at, event ID and delivery
deadline are retained; closed or13-day-old receipts never create replacement messages. New
recipients/revisions remain distinct. Legacy duplicate receipts are not deleted. No new migration.

The worker renders the current saved scope even for a delayed old callback/refresh, but only acts
on IDs from the actual clicked button. Deploy the matching worker first, then Guardian. Older
Guardian processes can still send per-stage cards during rollout overlap; only the new Ensure
path coordinates producers. Callback/operator/receipt validation and policy checks still apply.

A pure domain planner groups approvals by their actual stage index. It includes the recipient's
ready steps, then eligible consecutive manual stages, stopping where another approver, self-approval
restriction or unresolved automatic check prevents completion. Only people with a pending step
receive notifications. lark_v2 expansion respects admitted pending-step criteria. Receipt lookup
adds the current bounded approval_plan; the existing appeal/step API remains unchanged. Reconciliation
can extend legacy receipts with consecutive blocked future IDs only if all ready seed IDs were
already admitted. It preserves event/message/created_at and fences older leases through Ensure.
The shared fingerprint includes plan membership so changed barriers repaint the actions.

Public notification fields now include typed package linkage, allowlisted package-creation details
and the committed grant expiry. No package-name lookup is added to the approval commit path; all
notification transport still runs asynchronously after commit. Existing provider-before-commit race
limitations remain separate. No migration or new runtime credential is needed.


## Slow approval and reminder fixes

Approval keeps its existing pre-check/provider-work/locked-commit flow. This change
adds no approval execution table, durable admission, heartbeat, advisory lock,
background decision endpoint or database migration. Concurrent Console/Lark calls
can still overlap provider work before commit; ambiguous outcomes still require
checking before another explicit attempt. These existing risks are accepted.

Post-hooks retain their existing detached behavior, bounded by
POST_APPEAL_HOOK_TIMEOUT_SECONDS (default1800, range60..86400). The post-hook timeout
is separate from caller HTTP timeouts; it is not an approval lock. Dependency
errgroup cancellation no longer replaces the context used for subsequent hooks.
Successful hook response bodies are closed. A stable X-Guardian-Operation-ID header
binds each hook to its appeal/revision/name. Dex package creation stores that identity
and a canonical request hash on the created resource; an identical replay returns
that resource, while different requests still conflict. Dex provisioning remains
asynchronous and has its existing retry mechanism. Deploy Dex replay support before
relying on this recovery behavior.

The worker's existing queue shows processing feedback and waits longer using its
configurable action budget. No new receipt schema or state field is required.
Notification failure does not roll back approval or prevent the worker's decision.

Pending reminders count distinct appeals per normalized recipient. Query/row-read
errors are returned before any sends. Per-recipient delivery failures are logged
and skipped while other recipients continue; the whole Job remains successful.
No reminder-delivery table, daily key, application timezone or exact-once promise
is added. Scheduling/timezone and retry policy belong to deployment configuration;
manual reruns may resend reminders.
