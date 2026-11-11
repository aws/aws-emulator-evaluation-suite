"""alias-update-stale-revision-rejected."""
from __future__ import annotations

import io
import json
import time
import zipfile

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "alias-update-stale-revision-rejected"
GROUP = "state-machine"
SERVICES = ["lambda"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateAlias with a stale RevisionId is rejected with PreconditionFailedException."""
    lam = ctx.client("lambda")
    fn = _create_basic_function(ctx)
    version = lam.publish_version(FunctionName=fn["name"])["Version"]
    alias_name = ctx.unique_name("sim2real-alias-stale-")

    created = lam.create_alias(FunctionName=fn["name"], Name=alias_name, FunctionVersion=version)
    ctx.on_cleanup(lambda: _delete_alias_ignore(lam, fn["name"], alias_name))
    stale_revision = created["RevisionId"]

    advanced = lam.update_alias(FunctionName=fn["name"], Name=alias_name, Description="advance revision")
    assert advanced["RevisionId"] != stale_revision, (
        f"expected RevisionId to advance past {stale_revision!r}, got {advanced['RevisionId']!r}"
    )

    code, code_msg = _error(
        lambda: lam.update_alias(
            FunctionName=fn["name"],
            Name=alias_name,
            Description="should be rejected",
            RevisionId=stale_revision,
        )
    )
    assert code == "PreconditionFailedException", f"expected PreconditionFailedException, got {code}"
    assert code_msg == (
        "The Revision Id provided does not match the latest Revision Id. "
        "Call the GetFunction/GetAlias API to retrieve the latest Revision Id"
    ), (
        f"expected the exact 'PreconditionFailedException' message, got {code_msg!r}"
    )

    # confirm the stale write never took effect
    got = lam.get_alias(FunctionName=fn["name"], Name=alias_name)
    assert got["Description"] == "advance revision", (
        f"rejected UpdateAlias must not have applied, got Description={got['Description']!r}"
    )


def _error(fn):
    """Run *fn*, which AWS must refuse; return the refusal's (code, message)."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded with {result!r}")


def _lambda_zip_bytes() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", "def handler(event, context):\n    return {'ok': True}\n")
    return buf.getvalue()


def _create_exec_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    return role["Role"]["Arn"]


def _create_basic_function(ctx) -> dict:
    lam = ctx.client("lambda")
    role_arn = _create_exec_role(ctx)
    name = ctx.unique_name("sim2real-behav-fn-")
    deadline = time.monotonic() + 90
    resp = None
    while time.monotonic() < deadline:
        try:
            resp = lam.create_function(
                FunctionName=name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="lambda_function.handler",
                Code={"ZipFile": _lambda_zip_bytes()},
                Timeout=10,
                MemorySize=128,
                Publish=False,
                Tags={"sim2real-check": CHECK},
            )
            break
        except Exception as e:
            if "cannot be assumed" in str(e) or "InvalidParameterValueException" in str(e):
                time.sleep(3)
                continue
            raise
    if resp is None:
        raise AssertionError("create_function never succeeded (role propagation timeout)")
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    _wait_function_active(ctx, name)
    return {"name": name, "arn": resp["FunctionArn"], "role_arn": role_arn}


def _wait_function_active(ctx, name: str) -> dict:
    lam = ctx.client("lambda")
    deadline = time.monotonic() + 90
    cfg = None
    while time.monotonic() < deadline:
        cfg = lam.get_function_configuration(FunctionName=name)
        if cfg["State"] == "Active":
            return cfg
        if cfg["State"] == "Failed":
            raise AssertionError(f"function entered Failed state: {cfg.get('StateReason')}")
        time.sleep(2)
    raise AssertionError(f"function did not become Active in time (last={cfg!r})")


def _delete_alias_ignore(lam, function_name: str, alias_name: str) -> None:
    from botocore.exceptions import ClientError

    try:
        lam.delete_alias(FunctionName=function_name, Name=alias_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
