"""list-function-url-configs-reflects."""
from __future__ import annotations

import io
import time
import zipfile
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "list-function-url-configs-reflects"
GROUP = "state-machine"
SERVICES = ["lambda"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx: Any) -> None:
    """URL configs created for $LATEST and for an alias are both listed by ListFunctionUrlConfigs,
    each with its own URL and its own AuthType/InvokeMode settings.

    Reference: https://docs.aws.amazon.com/lambda/latest/api/API_ListFunctionUrlConfigs.html
    """
    lam = ctx.client("lambda")
    role_arn = _create_basic_role(ctx)
    name = ctx.unique_name("sim2real-lurl-")
    zip_bytes = _zip_from_source("lambda_function.py", _BASIC_HANDLER)
    _create_function_with_retry(ctx, name=name, role_arn=role_arn, zip_bytes=zip_bytes)

    # A URL's Qualifier must be $LATEST or an alias; a numeric version is rejected, so alias it.
    version = lam.publish_version(FunctionName=name)["Version"]
    alias_name = ctx.unique_name("sim2real-lurl-alias-")
    lam.create_alias(FunctionName=name, Name=alias_name, FunctionVersion=version)
    ctx.on_cleanup(lambda: lam.delete_alias(FunctionName=name, Name=alias_name))

    lam.create_function_url_config(FunctionName=name, AuthType="AWS_IAM")
    ctx.on_cleanup(lambda: lam.delete_function_url_config(FunctionName=name))
    lam.create_function_url_config(
        FunctionName=name, Qualifier=alias_name, AuthType="AWS_IAM", InvokeMode="RESPONSE_STREAM"
    )
    ctx.on_cleanup(lambda: lam.delete_function_url_config(FunctionName=name, Qualifier=alias_name))

    configs = _poll_until(
        lambda: lam.list_function_url_configs(FunctionName=name)["FunctionUrlConfigs"],
        lambda cfgs: len(cfgs) >= 2,
        timeout_s=30.0,
        interval_s=2.0,
    )
    by_arn = {c["FunctionArn"]: c for c in configs}

    # The $LATEST config is reported with the bare function ARN (no ":$LATEST" suffix);
    # only the alias entry carries a ":<qualifier>" suffix.
    alias_arn = next((a for a in by_arn if a.endswith(f":{alias_name}")), None)
    assert alias_arn is not None, f"expected a :{alias_name} entry in {list(by_arn)}"
    latest_arn = next((a for a in by_arn if a != alias_arn), None)
    assert latest_arn is not None, f"expected a distinct $LATEST entry in {list(by_arn)}"

    latest_entry = by_arn[latest_arn]
    alias_entry = by_arn[alias_arn]

    assert latest_entry["AuthType"] == "AWS_IAM", (
        f"expected $LATEST AuthType AWS_IAM, got {latest_entry['AuthType']!r}"
    )
    assert alias_entry["InvokeMode"] == "RESPONSE_STREAM", (
        f"expected alias InvokeMode RESPONSE_STREAM, got {alias_entry['InvokeMode']!r}"
    )
    assert alias_entry["FunctionUrl"] != latest_entry["FunctionUrl"], "each qualifier gets its own URL"


_BASIC_HANDLER = "def lambda_handler(event, context):\n    return {'ok': True, 'event': event}\n"


def _zip_from_source(filename: str, source: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, source)
    return buf.getvalue()


def _poll_until(probe, predicate, timeout_s: float = 60.0, interval_s: float = 2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _create_basic_role(ctx: Any) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-lambda-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    import json

    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    role_arn = resp["Role"]["Arn"]
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)

    def _cleanup() -> None:
        try:
            iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    return role_arn


def _create_function_with_retry(
    ctx: Any,
    *,
    name: str,
    role_arn: str,
    zip_bytes: bytes,
    handler: str = "lambda_function.lambda_handler",
    runtime: str = "python3.12",
    timeout_s: float = 90.0,
) -> str:
    from botocore.exceptions import ClientError

    lam = ctx.client("lambda")
    deadline = time.monotonic() + timeout_s
    resp = None
    last_exc = None
    while time.monotonic() < deadline:
        try:
            ctx.on_cleanup(lambda _n=name: _delete_lambda_log_group(ctx, _n))
            resp = lam.create_function(
                FunctionName=name,
                Runtime=runtime,
                Role=role_arn,
                Handler=handler,
                Code={"ZipFile": zip_bytes},
                Timeout=30,
                MemorySize=128,
                Tags={"sim2real:managed": "true"},
            )
            break
        except ClientError as exc:
            last_exc = exc
            code = exc.response["Error"]["Code"]
            if code == "InvalidParameterValueException" and "role" in str(exc).lower():
                time.sleep(3)
                continue
            raise
    if resp is None:
        raise AssertionError(f"could not create function after retries: {last_exc}")
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    cfg = _poll_until(
        lambda: lam.get_function_configuration(FunctionName=name),
        lambda c: c["State"] in ("Active", "Failed"),
        timeout_s=90.0,
        interval_s=2.0,
    )
    if cfg["State"] != "Active":
        raise AssertionError(f"function failed to activate: {cfg.get('StateReason')}")
    return resp["FunctionArn"]


def _delete_lambda_log_group(ctx, function_name: str) -> None:
    """Delete the log group Lambda creates on a function's first log line, if it exists."""
    try:
        ctx.client("logs").delete_log_group(logGroupName=f"/aws/lambda/{function_name}")
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
