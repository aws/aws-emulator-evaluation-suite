"""deploy-missing-esm-source-arn-permission-negative."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-missing-esm-source-arn-permission-negative"
GROUP = "overly-permissive"
SERVICES = ["lambda", "s3", "sqs"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateEventSourceMapping for an SQS queue fails with InvalidParameterValueException (exact
    message) and creates no mapping when the function's role lacks sqs:ReceiveMessage; a role
    with the required permissions gets a mapping that reaches Enabled."""
    lam = ctx.client("lambda")

    # --- broken: role has logs-only permissions, no sqs:* at all ---
    broken_role_arn = _create_lambda_role(ctx, extra_statements=[], kind="role-broken")
    broken_fn = _create_function(ctx, broken_role_arn, "broken")
    _, broken_queue_arn = _create_queue(ctx, "broken-src")

    code, message = _expect_error(
        ctx,
        lam,
        lambda: lam.create_event_source_mapping(
            EventSourceArn=broken_queue_arn, FunctionName=broken_fn["name"], BatchSize=1
        ),
    )
    assert code == "InvalidParameterValueException", f"expected InvalidParameterValueException, got {code!r}"
    expected_message = "The function execution role does not have permissions to call ReceiveMessage on SQS"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    mappings = lam.list_event_source_mappings(FunctionName=broken_fn["name"])["EventSourceMappings"]
    assert mappings == [], f"expected no event source mapping to persist, found {mappings}"

    # --- positive control: role with the required sqs permissions succeeds ---
    _, ok_queue_arn = _create_queue(ctx, "ok-src")
    ok_role_arn = _create_lambda_role(
        ctx,
        extra_statements=[
            {
                "Effect": "Allow",
                "Action": ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes"],
                "Resource": ok_queue_arn,
            }
        ],
        kind="role-ok",
    )
    ok_fn = _create_function(ctx, ok_role_arn, "ok")
    esm = _create_esm_with_retry(lam, ok_queue_arn, ok_fn["name"])
    esm_uuid = esm["UUID"]
    ctx.on_cleanup(lambda: lam.delete_event_source_mapping(UUID=esm_uuid))
    state = _poll_until(
        lambda: lam.get_event_source_mapping(UUID=esm_uuid)["State"],
        lambda s: s in {"Enabled", "Disabled"},
        timeout_s=90,
        interval_s=3.0,
        description="control ESM reaching a steady state",
    )
    assert state == "Enabled", f"expected control ESM to reach Enabled, got {state!r}"


_XSVC_PREFIX = "sim2real-xsvc-"
_MANAGED_TAG_KEY = "sim2real:managed"


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _expect_error(ctx, lam, fn):
    """Call fn(); return the botocore Error (Code, Message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    uuid = result.get("UUID")
    if uuid:
        ctx.on_cleanup(lambda: lam.delete_event_source_mapping(UUID=uuid))
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _create_esm_with_retry(lam, queue_arn: str, function_name: str, *, timeout_s=30.0, interval_s=3.0):
    """CreateEventSourceMapping can transiently see the new role as not-yet-permission-propagated;
    retry on that specific code within a bounded deadline instead of a blind pre-emptive sleep."""
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return lam.create_event_source_mapping(
                EventSourceArn=queue_arn, FunctionName=function_name, BatchSize=1
            )
        except ClientError as e:
            if e.response["Error"]["Code"] != "InvalidParameterValueException":
                raise
            last_err = e
            time.sleep(interval_s)
    raise AssertionError(f"create_event_source_mapping never succeeded (IAM propagation?): {last_err}")


def _xsvc_resource_tags() -> dict:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _xname(ctx: Any, kind: str) -> str:
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _zip_bytes(code: str, filename: str = "index.py") -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, code)
    return buf.getvalue()


def _create_queue(ctx, kind: str):
    sqs = ctx.client("sqs")
    name = _xname(ctx, f"q-{kind}")
    url = sqs.create_queue(QueueName=name)["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return url, arn


def _create_lambda_role(ctx, extra_statements: list, kind: str = "role") -> str:
    iam = ctx.client("iam")
    name = _xname(ctx, kind)
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(
        RoleName=name, AssumeRolePolicyDocument=json.dumps(trust), Tags=_xsvc_tags_kv()
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    statements = [
        {
            "Effect": "Allow",
            "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
            "Resource": "*",
        }
    ] + list(extra_statements)
    policy_name = f"{name}-policy"
    iam.put_role_policy(
        RoleName=name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=name, PolicyName=policy_name))
    return role_arn


def _create_function(ctx, role_arn: str, kind: str) -> dict:
    lam = ctx.client("lambda")
    name = _xname(ctx, f"fn-{kind}")
    code = "def handler(event, context):\n    return {'ok': True}\n"
    kwargs = dict(
        FunctionName=name,
        Runtime="python3.12",
        Role=role_arn,
        Handler="index.handler",
        Code={"ZipFile": _zip_bytes(code)},
        Timeout=10,
        Tags=_xsvc_resource_tags(),
    )
    deadline = time.monotonic() + 30
    resp = None
    last_err = None
    while time.monotonic() < deadline:
        try:
            ctx.on_cleanup(lambda _n=name: _delete_lambda_log_group(ctx, _n))
            resp = lam.create_function(**kwargs)
            break
        except ClientError as e:
            if e.response["Error"]["Code"] == "InvalidParameterValueException" and "role" in str(e).lower():
                last_err = e
                time.sleep(3)
                continue
            raise
    if resp is None:
        raise last_err
    arn = resp["FunctionArn"]
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    _poll_until(
        lambda: lam.get_function(FunctionName=name)["Configuration"]["State"],
        lambda s: s in {"Active", "Failed"},
        timeout_s=60,
        interval_s=2.0,
        description=f"function {name} becoming active",
    )
    return {"name": name, "arn": arn}


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
