"""cli-script-lambda-deploy-and-invoke."""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cli-script-lambda-deploy-and-invoke"

GROUP = "cli-script"

SERVICES = ["lambda"]


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Bash script creates a Lambda from zip, invokes it, checks response."""
    role = _create_role(ctx, "lambda.amazonaws.com")
    fn_name = ctx.unique_name("cli-fn-")
    result = _run_script(
        ctx,
        f"""
        # Write the handler source via a quoted heredoc (no shell expansion) then zip it —
        # embedding a JSON-quoted dict literal inside a `python3 -c "..."` string is a nested-
        # quoting trap: any \" inside an f-string is collapsed to " by Python's own literal
        # parser before bash ever sees it, so bash's quote scanner closes the outer -c string
        # early and mangles the handler source (silently, into invalid Python).
        cat > /tmp/cli-fn-handler.py <<'PYEOF'
def lambda_handler(e, c):
    return {{"hello": "cli-deploy"}}
PYEOF
        python3 -c "
import zipfile
with zipfile.ZipFile('/tmp/cli-fn.zip', 'w') as zf:
    zf.write('/tmp/cli-fn-handler.py', 'lambda_function.py')
"

        # create-function can transiently fail with "The role defined for the
        # function cannot be assumed by Lambda" while a freshly created role
        # propagates. Retry on that message only, for up to 90s.
        for i in $(seq 1 18); do
            if aws lambda create-function \\
                --function-name {fn_name} \\
                --runtime python3.12 \\
                --role {role["arn"]} \\
                --handler lambda_function.lambda_handler \\
                --zip-file fileb:///tmp/cli-fn.zip \\
                --output json > /dev/null 2>/tmp/cli-fn-err.txt; then
                break
            fi
            if grep -qi "cannot be assumed" /tmp/cli-fn-err.txt && [ "$i" -lt 18 ]; then sleep 5; continue; fi
            cat /tmp/cli-fn-err.txt >&2; exit 1
        done

        # Wait for a terminal state; anything but Active fails the script
        for i in $(seq 1 45); do
            STATE=$(aws lambda get-function-configuration --function-name {fn_name} --query State --output text)
            if [ "$STATE" = "Active" ] || [ "$STATE" = "Failed" ]; then break; fi
            sleep 2
        done
        if [ "$STATE" != "Active" ]; then echo "function state $STATE, expected Active" >&2; exit 1; fi

        # CLI v2 requires --cli-binary-format raw-in-base64-out to pass a raw-JSON
        # --payload (else "Invalid base64"); the passing cli-lambda-create-invoke
        # check uses it, this one omitted it.
        aws lambda invoke --function-name {fn_name} --cli-binary-format raw-in-base64-out --payload '{{}}' /tmp/cli-fn-out.json > /dev/null
        cat /tmp/cli-fn-out.json
    """,
        timeout_s=300.0,
    )
    ctx.on_cleanup(lambda: ctx.client("lambda").delete_function(FunctionName=fn_name))
    # The function auto-creates /aws/lambda/<name> on first invoke; that log group survives
    # function deletion, so delete it explicitly.
    ctx.on_cleanup(lambda: _delete_log_group_if_present(ctx, f"/aws/lambda/{fn_name}"))
    assert json.loads(result.stdout) == {"hello": "cli-deploy"}, (
        f"expected invoke payload {{'hello': 'cli-deploy'}}, got: {result.stdout!r}"
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


def _create_role(
    ctx, trust_service, inline_policy=None, managed_policies=None
) -> dict[str, str]:
    """Create an IAM role and register its (policy-detach-then-delete) teardown. Returns {name,arn}."""
    iam = ctx.client("iam")
    role_name = _xname(ctx, f"role-{trust_service.split('.')[0]}")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": trust_service},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Path="/sim2real/",
        Tags=_xsvc_tags_kv(),
    )
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    for policy_arn in managed_policies or []:
        iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    if inline_policy:
        iam.put_role_policy(
            RoleName=role_name,
            PolicyName="inline",
            PolicyDocument=json.dumps(inline_policy),
        )
    return {"name": role_name, "arn": resp["Role"]["Arn"]}


def _delete_log_group_if_present(ctx, name: str) -> None:
    """Delete the function's log group; Lambda creates it asynchronously, so it may not exist yet."""
    try:
        ctx.client("logs").delete_log_group(logGroupName=name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


def _delete_role(ctx, role_name: str) -> None:
    """IAM roles need every attached + inline policy removed before deletion."""
    iam = ctx.client("iam")
    try:
        for p in iam.list_attached_role_policies(RoleName=role_name).get(
            "AttachedPolicies", []
        ):
            iam.detach_role_policy(RoleName=role_name, PolicyArn=p["PolicyArn"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _run_script(ctx, script: str, *, timeout_s=120.0, check=True, env_extra=None):
    """Run a multi-line bash script (set -euo pipefail) with the run's AWS creds configured."""

    with tempfile.NamedTemporaryFile(mode="w", suffix=".sh", delete=False) as f:
        f.write("#!/bin/bash\nset -euo pipefail\n")
        f.write(script)
        script_path = f.name
    try:
        os.chmod(script_path, 0o755)
        return _run_shell(
            ctx,
            ["bash", script_path],
            timeout_s=timeout_s,
            check=check,
            env_extra=env_extra,
        )
    finally:
        os.unlink(script_path)


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
