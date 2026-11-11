"""cli-iam-role-lifecycle."""

from __future__ import annotations

import json
import re
import subprocess

from botocore.exceptions import ClientError

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "cli-iam-role-lifecycle"

GROUP = "cli-roundtrip"

SERVICES = ["iam"]


@tags(
    "axis:happy-path",
    "cap:c1",
    "concern:representation",
    "concern:negative-classes",
    "plane:control",
)
def run(ctx) -> None:
    """IAM create-role -> get-role -> list-roles -> delete-role via CLI, with the delete
    proven gone (independent read + list) and unusable (a mutation on the dead role)."""
    require_tools("aws")
    role_name = ctx.unique_name("cli-role-")
    trust = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "lambda.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
    )
    _run_aws(
        ctx,
        "iam",
        "create-role",
        "--role-name",
        role_name,
        "--assume-role-policy-document",
        trust,
        "--path",
        "/sim2real/",
        "--tags",
        "Key=sim2real-behav,Value=cli-iam-role-lifecycle",
    )
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))

    result = _run_aws(ctx, "iam", "get-role", "--role-name", role_name)
    assert result["Role"]["RoleName"] == role_name, (
        f"expected RoleName {role_name!r}, got {result['Role'].get('RoleName')!r}"
    )
    assert result["Role"]["Path"] == "/sim2real/", (
        f"expected Path '/sim2real/', got {result['Role'].get('Path')!r}"
    )

    listed = _run_aws(ctx, "iam", "list-roles", "--path-prefix", "/sim2real/")
    names_before = {r["RoleName"] for r in listed.get("Roles", [])}
    assert role_name in names_before, (
        f"expected {role_name!r} in list-roles --path-prefix /sim2real/, got {names_before}"
    )

    _delete_role(ctx, role_name)

    code = _aws_error_code(ctx, "iam", "get-role", "--role-name", role_name)
    assert code == "NoSuchEntity", f"expected NoSuchEntity after delete, got {code!r}"

    listed_after = _run_aws(ctx, "iam", "list-roles", "--path-prefix", "/sim2real/")
    names_after = {r["RoleName"] for r in listed_after.get("Roles", [])}
    assert role_name not in names_after, (
        f"expected {role_name!r} absent from list-roles after delete, got {names_after}"
    )

    tag_code = _aws_error_code(
        ctx,
        "iam",
        "tag-role",
        "--role-name",
        role_name,
        "--tags",
        "Key=post-delete,Value=probe",
    )
    assert tag_code == "NoSuchEntity", (
        f"expected NoSuchEntity tagging a deleted role, got {tag_code!r}"
    )


# ===== helpers =====
def _delete_role(ctx, role_name: str) -> None:
    """IAM roles need every attached + inline policy removed before deletion. Idempotent —
    safe to call once explicitly mid-check and again from ctx.on_cleanup."""
    iam = ctx.client("iam")
    try:
        for p in iam.list_attached_role_policies(RoleName=role_name).get(
            "AttachedPolicies", []
        ):
            iam.detach_role_policy(RoleName=role_name, PolicyArn=p["PolicyArn"])
        for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
        iam.delete_role(RoleName=role_name)
    except ClientError as e:
        if e.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _run_aws(ctx, *args: str, timeout_s=30.0, check=True):
    """Run an AWS CLI command; return parsed JSON (dict/list) or raw stdout string."""
    proc = _run_shell(
        ctx,
        ["aws", "--output", "json", "--no-cli-pager", *args],
        timeout_s=timeout_s,
        check=check,
    )
    if not proc.stdout.strip():
        return {}
    try:
        return json.loads(proc.stdout)
    except (json.JSONDecodeError, ValueError):
        return proc.stdout.strip()


def _aws_error_code(ctx, *args: str, timeout_s=30.0) -> str:
    """Run an AWS CLI command expected to fail; return the specific error code. Raises if it
    unexpectedly succeeds, so an accepted request never reads as a code mismatch."""
    proc = _run_shell(
        ctx,
        ["aws", "--output", "json", "--no-cli-pager", *args],
        timeout_s=timeout_s,
        check=False,
    )
    if proc.returncode == 0:
        raise AssertionError(
            f"expected {list(args)} to fail, but it succeeded: {proc.stdout[:300]}"
        )
    match = re.search(r"An error occurred \((\w+)\)", proc.stderr)
    if not match:
        raise AssertionError(
            f"could not parse error code from stderr: {proc.stderr[-300:]}"
        )
    return match.group(1)


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
