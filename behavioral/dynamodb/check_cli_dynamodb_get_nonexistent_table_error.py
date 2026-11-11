"""cli-dynamodb-get-nonexistent-table-error."""

from __future__ import annotations

import subprocess
from typing import Any

from fidelity_tests_runner import require_tools

from behavioral_harness import tags

CHECK = "cli-dynamodb-get-nonexistent-table-error"

GROUP = "overly-permissive"

SERVICES = ["dynamodb"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetItem on non-existent table via CLI must fail; the identical call against a real table
    (positive control) must succeed, so the failure is attributable to the missing table and not to
    broken CLI wiring or credentials."""
    require_tools("aws")
    table = _create_table(ctx)
    key_json = '{"pk":{"S":"x"}}'
    control = _run_shell(
        ctx, f"aws dynamodb get-item --table-name {table['name']} --key '{key_json}'"
    )
    assert control.returncode == 0, f"Positive control failed: {control.stderr[-300:]}"

    proc = _run_shell(
        ctx,
        f"aws dynamodb get-item --table-name does-not-exist-sim2real --key '{key_json}'",
        check=False,
    )
    assert proc.returncode != 0, "Expected failure for non-existent table"
    assert "ResourceNotFoundException" in proc.stderr, (
        f"Expected ResourceNotFoundException in stderr, got: {proc.stderr[-300:]}"
    )


_XSVC_PREFIX = "sim2real-xsvc-"

_MANAGED_TAG_KEY = "sim2real:managed"


def _xsvc_resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _xname(ctx: Any, kind: str) -> str:
    """A unique, prefix-tagged resource name: sim2real-xsvc-<kind>-<uuid>."""
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _create_table(ctx) -> dict[str, str]:
    """Create a DynamoDB table (PAY_PER_REQUEST; waits table_exists; registers delete_table).
    Returns {name,arn}."""
    name = _xname(ctx, "tbl")
    ddb = ctx.client("dynamodb")
    resp = ddb.create_table(
        TableName=name,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=_xsvc_tags_kv(),
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=name))
    ddb.get_waiter("table_exists").wait(
        TableName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 30}
    )
    return {"name": name, "arn": resp["TableDescription"]["TableArn"]}


def _run_shell(ctx, command, *, env_extra=None, timeout_s=60.0, check=True, cwd=None):
    """Run a shell command (str → shell=True, or argv list) with the run's AWS creds + region in the
    env (via ctx.subprocess_env). Raises on non-zero exit when check=True. Returns CompletedProcess."""
    ctx.verify_account_safety()
    env = ctx.subprocess_env()
    if env_extra:
        env.update(env_extra)
    result = subprocess.run(
        command,
        shell=isinstance(command, str),
        env=env,
        capture_output=True,
        text=True,
        timeout=timeout_s,
        cwd=cwd,
    )
    if check and result.returncode != 0:
        raise AssertionError(
            f"Command failed (rc={result.returncode}):\n  cmd: {command}\n"
            f"  stderr: {result.stderr[-500:]}"
        )
    return result


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
