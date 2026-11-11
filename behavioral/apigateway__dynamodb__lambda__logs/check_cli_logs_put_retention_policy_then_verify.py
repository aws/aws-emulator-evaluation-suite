"""cli-logs-put-retention-policy-then-verify."""
from __future__ import annotations

import json
import subprocess
import time

from behavioral_harness import tags

CHECK = "cli-logs-put-retention-policy-then-verify"
GROUP = "cli-roundtrip"
SERVICES = ["apigateway", "dynamodb", "lambda", "logs"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CLI: put a retention policy on a log group, then verify describe-log-groups reports
    the persisted retentionInDays value."""
    from fidelity_tests_runner import require_tools

    require_tools("aws")

    log_group_name = ctx.unique_name("sim2real-behav-lg-")
    _run_aws(
        ctx, "logs", "create-log-group", "--log-group-name", log_group_name,
        "--tags", "Sim2RealOwner=behavioral-suite",
    )
    ctx.on_cleanup(lambda: _run_aws(ctx, "logs", "delete-log-group", "--log-group-name", log_group_name, check=False))

    before = _run_aws(ctx, "logs", "describe-log-groups", "--log-group-name-prefix", log_group_name)
    before_groups = before.get("logGroups", [])
    assert before_groups and "retentionInDays" not in before_groups[0], (
        f"freshly created log group should have no retention policy set, got {before_groups}"
    )

    _run_aws(ctx, "logs", "put-retention-policy", "--log-group-name", log_group_name, "--retention-in-days", "7")

    retention = _poll_for_retention(ctx, log_group_name, timeout_s=30.0)
    assert retention == 7, f"expected retentionInDays=7, got {retention}"



def _run_shell(ctx, command, *, env_extra=None, timeout_s=60.0, check=True, cwd=None):
    ctx.verify_account_safety()
    env = ctx.subprocess_env()
    if env_extra:
        env.update(env_extra)
    result = subprocess.run(
        command, shell=isinstance(command, str), env=env,
        capture_output=True, text=True, timeout=timeout_s, cwd=cwd,
    )
    if check and result.returncode != 0:
        raise AssertionError(
            f"Command failed (rc={result.returncode}):\n  cmd: {command}\n"
            f"  stderr: {result.stderr[-500:]}"
        )
    return result


def _run_aws(ctx, *args, timeout_s=30.0, check=True):
    proc = _run_shell(ctx, ["aws", "--output", "json", *args], timeout_s=timeout_s, check=check)
    if not proc.stdout.strip():
        return {}
    try:
        return json.loads(proc.stdout)
    except (json.JSONDecodeError, ValueError):
        return proc.stdout.strip()


def _poll_for_retention(ctx, log_group_name, timeout_s=30.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        result = _run_aws(
            ctx, "logs", "describe-log-groups", "--log-group-name-prefix", log_group_name,
        )
        groups = result.get("logGroups", [])
        if groups:
            last = groups[0].get("retentionInDays")
            if last == 7:
                return last
        time.sleep(2)
    return last


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
