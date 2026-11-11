"""lambda-sesv2-account-suppression-list-permission-negative."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

import botocore

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "lambda-sesv2-account-suppression-list-permission-negative"
GROUP = "permission-boundary"
SERVICES = ["lambda", "sesv2"]


@tags("axis:rejection", "cap:c3", "cap:c7", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Lambda role without ses:ListSuppressedDestinations gets AccessDeniedException querying the
    account suppression list, and granting the same role the permission makes the identical call
    succeed, so IAM enforces that action (no entry is needed, as the sandbox refuses seeding one)."""
    ses = ctx.client("sesv2")

    # positive control, before anything is broken: the caller's own permitted credentials can call
    # the operation at all, so a later AccessDeniedException is attributable to the missing grant
    # and not to some account-wide block on the operation itself.
    control = ses.list_suppressed_destinations()
    assert isinstance(control.get("SuppressedDestinationSummaries"), list), (
        f"account/credentials must be healthy for ses:ListSuppressedDestinations before anything is "
        f"broken; got {control!r}"
    )

    iam = ctx.client("iam")
    role_name, role_arn = _create_lambda_role(ctx)
    handler_src = """
import boto3
import botocore

def handler(event, context):
    client = boto3.client("sesv2")
    try:
        resp = client.list_suppressed_destinations()
        return {"ok": True, "addresses": [d["EmailAddress"] for d in resp.get("SuppressedDestinationSummaries", [])]}
    except botocore.exceptions.ClientError as err:
        return {"ok": False, "error_code": err.response["Error"]["Code"]}
"""
    function_name = _create_function(ctx, role_arn, handler_src)

    result = _invoke(ctx, function_name, {})
    assert result["function_error"] is None, f"lambda invocation raised: {result}"
    body = result["body"]
    assert body["ok"] is False, f"role lacks ses:ListSuppressedDestinations, expected a refusal: {body}"
    assert body["error_code"] == "AccessDeniedException", (
        f"expected AccessDeniedException for the unpermitted role, got {body['error_code']!r}"
    )
    assert "addresses" not in body, f"a denied call must not carry the collection it was denied: {body}"

    # restore: grant the SAME role the permission and demand the identical call now succeeds.
    policy_name = ctx.unique_name("sim2real-lsesv2-grant-")
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "ses:ListSuppressedDestinations", "Resource": "*"}],
        }),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))

    deadline = time.monotonic() + 90
    restored_body: dict | None = None
    while time.monotonic() < deadline:
        retry = _invoke(ctx, function_name, {})
        assert retry["function_error"] is None, f"lambda invocation raised after granting permission: {retry}"
        restored_body = retry["body"]
        if restored_body["ok"] is True:
            break
        assert restored_body["error_code"] == "AccessDeniedException", (
            f"expected the grant to propagate as AccessDeniedException until it takes effect, got "
            f"{restored_body}"
        )
        time.sleep(3)
    else:
        raise AssertionError(
            f"granting ses:ListSuppressedDestinations to the role never took effect within 90s; "
            f"last body {restored_body}"
        )

    assert restored_body["ok"] is True, (
        f"the identical call must succeed once the SAME role is granted the permission; got {restored_body}"
    )
    assert isinstance(restored_body["addresses"], list), (
        f"the restored call must return the real collection, not merely ok=True; got {restored_body}"
    )


# ===== helpers =====
_PREFIX = "sim2real-lsesv2-"


def _xname(ctx: Any, kind: str) -> str:
    return ctx.unique_name(f"{_PREFIX}{kind}-")


def _lambda_trust_policy() -> str:
    return json.dumps(
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


def _create_lambda_role(ctx: Any) -> tuple[str, str]:
    iam = ctx.client("iam")
    role_name = _xname(ctx, "role")
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=_lambda_trust_policy(),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    role_arn = role["Role"]["Arn"]
    iam.attach_role_policy(
        RoleName=role_name,
        PolicyArn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
    )

    def _cleanup() -> None:
        try:
            iam.detach_role_policy(
                RoleName=role_name,
                PolicyArn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup)
    return role_name, role_arn


def _zip_code(handler_src: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", handler_src)
    return buf.getvalue()


def _create_function(ctx: Any, role_arn: str, handler_src: str, timeout: int = 30) -> str:
    lam = ctx.client("lambda")
    name = _xname(ctx, "fn")
    code = _zip_code(handler_src)
    deadline = time.monotonic() + 90
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            ctx.on_cleanup(lambda _n=name: _delete_lambda_log_group(ctx, _n))
            lam.create_function(
                FunctionName=name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="lambda_function.handler",
                Code={"ZipFile": code},
                Timeout=timeout,
                MemorySize=128,
                Tags={"sim2real": CHECK},
            )
            break
        except botocore.exceptions.ClientError as err:
            err_code = err.response["Error"]["Code"]
            if err_code == "InvalidParameterValueException" and "role" in str(err).lower():
                last_err = err
                time.sleep(3)
                continue
            raise
    else:
        raise AssertionError(f"role never became assumable by Lambda: {last_err}")
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    lam.get_waiter("function_active_v2").wait(FunctionName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})
    return name


def _invoke(ctx: Any, function_name: str, payload: dict | None = None) -> dict:
    lam = ctx.client("lambda")
    resp = lam.invoke(
        FunctionName=function_name,
        Payload=json.dumps(payload or {}).encode("utf-8"),
    )
    body = json.loads(resp["Payload"].read())
    return {"function_error": resp.get("FunctionError"), "body": body}


def _delete_lambda_log_group(ctx, function_name: str) -> None:
    """Delete the log group Lambda creates on a function's first log line; one never created is fine."""
    try:
        ctx.client("logs").delete_log_group(logGroupName=f"/aws/lambda/{function_name}")
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
