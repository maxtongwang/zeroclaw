# ZeroClaw Operations Runbook

This runbook is for operators who maintain availability, security posture, and incident response.

Last verified: **February 18, 2026**.

## Scope

Use this document for day-2 operations:

- starting and supervising runtime
- health checks and diagnostics
- safe rollout and rollback
- incident triage and recovery

For first-time installation, start from [one-click-bootstrap.md](one-click-bootstrap.md).

## Runtime Modes

| Mode                    | Command                                              | When to use                           |
| ----------------------- | ---------------------------------------------------- | ------------------------------------- |
| Foreground runtime      | `zeroclaw daemon`                                    | local debugging, short-lived sessions |
| Foreground gateway only | `zeroclaw gateway`                                   | webhook endpoint testing              |
| User service            | `zeroclaw service install && zeroclaw service start` | persistent operator-managed runtime   |

## Baseline Operator Checklist

1. Validate configuration:

```bash
zeroclaw status
```

2. Verify diagnostics:

```bash
zeroclaw doctor
zeroclaw channel doctor
```

3. Start runtime:

```bash
zeroclaw daemon
```

4. For persistent user session service:

```bash
zeroclaw service install
zeroclaw service start
zeroclaw service status
```

## Health and State Signals

| Signal                 | Command / File                  | Expected                         |
| ---------------------- | ------------------------------- | -------------------------------- |
| Config validity        | `zeroclaw doctor`               | no critical errors               |
| Channel connectivity   | `zeroclaw channel doctor`       | configured channels healthy      |
| Runtime summary        | `zeroclaw status`               | expected provider/model/channels |
| Daemon heartbeat/state | `~/.zeroclaw/daemon_state.json` | file updates periodically        |

## Logs and Diagnostics

### macOS / Windows (service wrapper logs)

- `~/.zeroclaw/logs/daemon.stdout.log`
- `~/.zeroclaw/logs/daemon.stderr.log`

### Linux (systemd user service)

```bash
journalctl --user -u zeroclaw.service -f
```

## Incident Triage Flow (Fast Path)

1. Snapshot system state:

```bash
zeroclaw status
zeroclaw doctor
zeroclaw channel doctor
```

2. Check service state:

```bash
zeroclaw service status
```

3. If service is unhealthy, restart cleanly:

```bash
zeroclaw service stop
zeroclaw service start
```

4. If channels still fail, verify allowlists and credentials in `~/.zeroclaw/config.toml`.

5. If gateway is involved, verify bind/auth settings (`[gateway]`) and local reachability.

## Channel-Specific Operations

### BlueBubbles (iMessage)

**Server requirements:**

- Self-hosted [BlueBubbles server](https://bluebubbles.app) running on macOS with iMessage signed in.
- Server must be reachable from the ZeroClaw host (LAN or internet; HTTPS recommended for remote access).

**Webhook setup:**

1. In the BlueBubbles server UI, add a webhook URL pointing to:
   `http(s)://<zeroclaw-host>:<gateway-port>/bluebubbles`
2. Set the webhook type to **All Notifications** (or at minimum _New Messages_ and _Updated Messages_).
3. Copy the webhook password/secret shown by BlueBubbles.

**Config:**

```toml
[channels_config.bluebubbles]
server_url = "https://bb.example.com"
password = "your-bb-password"
webhook_secret = "your-webhook-secret"   # optional but recommended
dm_policy = "open"
group_policy = "open"
```

Set `webhook_secret` to the same secret configured in the BlueBubbles server UI to enable HMAC signature verification on incoming webhooks.

**Health check:**

```bash
zeroclaw channel doctor
```

Look for `BlueBubbles` in the output. A healthy channel shows `ok`; unhealthy means the server URL or password is unreachable or invalid.

**Startup/upgrade steps:**

1. Restart the ZeroClaw daemon after any BlueBubbles config change.
2. After upgrading BlueBubbles server, verify the webhook URL is still registered and re-test with `zeroclaw channel doctor`.

## Secret Leak Incident Response (CI Gitleaks)

When `sec-audit.yml` reports a gitleaks finding or uploads SARIF alerts:

1. Confirm whether the finding is a true credential leak or a test/doc false positive:
    - review `gitleaks.sarif` + `gitleaks-summary.json` artifacts
    - inspect changed commit range in the workflow summary
2. If true positive:
    - revoke/rotate the exposed secret immediately
    - remove leaked material from reachable history when required by policy
    - open an incident record and track remediation ownership
3. If false positive:
    - prefer narrowing detection scope first
    - only add allowlist entries with explicit governance metadata (`owner`, `reason`, `ticket`, `expires_on`)
    - ensure the related governance ticket is linked in the PR
4. Re-run `Sec Audit` and confirm:
    - gitleaks lane green
    - governance guard green
    - SARIF upload succeeds

## Safe Change Procedure

Before applying config changes:

1. backup `~/.zeroclaw/config.toml`
2. apply one logical change at a time
3. run `zeroclaw doctor`
4. restart daemon/service
5. verify with `status` + `channel doctor`

## Rollback Procedure

If a rollout regresses behavior:

1. restore previous `config.toml`
2. restart runtime (`daemon` or `service`)
3. confirm recovery via `doctor` and channel health checks
4. document incident root cause and mitigation

## Related Docs

- [one-click-bootstrap.md](one-click-bootstrap.md)
- [troubleshooting.md](troubleshooting.md)
- [config-reference.md](config-reference.md)
- [commands-reference.md](commands-reference.md)
