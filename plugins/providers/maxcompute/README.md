# MaxCompute access verification

For RAM users and RAM roles, `GrantAccess` and `RevokeAccess` return success only after a fresh MaxCompute read confirms every requested assignment. Project membership uses `LIST USERS`, project roles use `SHOW GRANTS FOR`, schema roles use CatalogAPI `getPolicy`, and direct table permissions use `SHOW GRANTS ON TABLE`.

## Configuration

The optional `access_verification_timeout_seconds` field belongs inside the provider's existing `config.credentials` object. Omit it to use 15 seconds. An explicit value must be a positive integer.

```yaml
config:
  credentials:
    # Add this field alongside the existing credential configuration.
    access_verification_timeout_seconds: 15
```

Readback starts immediately and returns as soon as the complete expected state is observed. Subsequent waits are 1, 2, 4, then at most 5 seconds. One deadline covers all assignments, all retries, and in-flight verification requests. An earlier caller deadline takes precedence. The 15-second budget is additional to credential initialization and mutation; the mutation phase has a separate 30-second bound. Sequential dependency grants can also add time to the enclosing appeal request.

## Meaning of success and failure

- Verification confirms stored cloud assignments. Query execution can still lag due to MaxCompute propagation or be denied by another policy.
- Revocation checks the assignments on the requested scope. Other roles, inherited permissions, and implicit owner privileges are not removed to force a total loss of effective access.
- A schema grant also confirms its configured default project binding. A schema revoke preserves that shared project binding.
- A project membership revoke retains the existing behavior of detaching project roles when MaxCompute returns `DeleteConflict`, but now bounds the cleanup attempts.
- `All` satisfies ordinary direct table permissions. Cold-storage actions require explicit readback; the verifier does not assume `All` includes tenant-specific cold permissions. Revoking `All` requires an empty direct ACL for the principal.
- Package accounts remain metadata-only no-ops. Explicit provider-skip operations do not invoke verification.

`ErrAccessUnconfirmed` and `AccessVerificationError` identify an unconfirmed change. The error includes the operation, resource, unresolved assignments, and attempt count; its wrapped cause preserves deadline and read errors. A failed, malformed, or incomplete read never proves absence.

An ambiguous write response is followed by readback rather than a blind replay. A timeout does not undo cloud changes, and a multi-permission operation may leave partial changes when it fails. Retry the requested operation after inspecting the reported outcome. The provider does not recursively compensate a failed grant with revocation, or a failed revoke with a grant. Accepted asynchronous commands may complete after the caller has stopped waiting.

The shared revoke service restores the original Guardian record if the provider fails. Its cleanup is separately bounded to five seconds and still runs after request cancellation. If cleanup fails too, the returned error preserves both failures. This is not a distributed transaction: the cloud and database can still differ after an uncertain outcome.

## Operations and validation

Verification emits structured logs with operation, resource, attempts, elapsed milliseconds, and outcome. It does not log credentials or raw cloud responses. Review duration and unconfirmed counts before changing the configured window.

The existing bulk `ListAccess` and `ListAccessForUsers` methods remain best-effort. The verifier does not use them. Their drift-repair semantics are outside this change.

```sh
go test -mod=readonly ./plugins/providers/maxcompute ./pkg/alicatalogapis ./core/grant ./core/appeal
go test -mod=readonly -race ./plugins/providers/maxcompute ./pkg/alicatalogapis ./core/grant
go vet -mod=readonly ./plugins/providers/maxcompute ./pkg/alicatalogapis ./core/grant
```

Before production rollout, use isolated staging fixtures to validate grant/revoke readback for project membership and roles, private schema bindings, and ordinary/cold table actions. Include propagation beyond the configured window, confirm no false success, and measure readback latency. Offline tests do not establish live latency or deployed behavior.
