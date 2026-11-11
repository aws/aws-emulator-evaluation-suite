"""check-kinesis-esm-fails-without-permissions."""

from __future__ import annotations

import json
import textwrap
import time
import zipfile
from io import BytesIO
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "check-kinesis-esm-fails-without-permissions"

GROUP = "overly-permissive"

SERVICES = ["dynamodb", "kinesis", "lambda"]


def _create_stream(ctx, shard_count: int = 1) -> dict:
    """Create a Kinesis data stream, wait for ACTIVE, and register cleanup.

    Returns {"name", "arn", "shard_count"}.
    """
    kinesis = ctx.client("kinesis")
    name = ctx.unique_name("kin-")
    kinesis.create_stream(StreamName=name, ShardCount=shard_count)
    ctx.on_cleanup(
        lambda: kinesis.delete_stream(StreamName=name, EnforceConsumerDeletion=True)
    )
    desc = _wait_for_effect(
        lambda: kinesis.describe_stream(StreamName=name)["StreamDescription"],
        lambda d: d.get("StreamStatus") == "ACTIVE",
        timeout_s=120,
    )
    return {"name": name, "arn": desc["StreamARN"], "shard_count": shard_count}


_KINESIS_READ_ACTIONS = [
    "kinesis:GetRecords",
    "kinesis:GetShardIterator",
    "kinesis:DescribeStream",
    "kinesis:DescribeStreamSummary",
    "kinesis:ListShards",
]


def _create_esm_retrying_role_propagation(lambda_client, **kwargs) -> dict:
    """Kinesis ESM creation validates the execution role's stream permissions synchronously,
    but a just-granted IAM policy can take up to ~60s to become visible to that check. Retry
    while the specific permission error recurs; any other error, or a timeout, propagates."""
    deadline = time.monotonic() + 60
    last_err = None
    while time.monotonic() < deadline:
        try:
            return lambda_client.create_event_source_mapping(**kwargs)
        except ClientError as e:
            if e.response["Error"]["Code"] == "InvalidParameterValueException":
                last_err = e
                time.sleep(3)
                continue
            raise
    raise last_err


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Creating a Kinesis event source mapping must fail when the Lambda role lacks stream read
    permissions, and the identical call must succeed once the role has been granted them."""
    stream = _create_stream(ctx, shard_count=1)
    lambda_client = ctx.client("lambda")

    code = """
def handler(event, context):
    return {"ok": True}
"""

    # Positive control: a role with the documented Kinesis read permissions must be allowed to
    # create the mapping, proving the stream and account are otherwise healthy for this call.
    control_fn = _create_lambda(
        ctx,
        code,
        permissions=[{"Action": _KINESIS_READ_ACTIONS, "Resource": stream["arn"]}],
    )
    control_resp = _create_esm_retrying_role_propagation(
        lambda_client,
        EventSourceArn=stream["arn"],
        FunctionName=control_fn["name"],
        StartingPosition="TRIM_HORIZON",
    )
    ctx.on_cleanup(
        lambda uuid=control_resp["UUID"]: lambda_client.delete_event_source_mapping(
            UUID=uuid
        )
    )
    assert control_resp["State"] in ("Creating", "Enabled"), (
        f"positive control: ESM creation with granted permissions did not reach a live "
        f"state, got {control_resp['State']!r}"
    )

    # Break exactly one thing: a role with zero kinesis permissions.
    role = _create_role(
        ctx,
        "lambda.amazonaws.com",
        inline_policy={
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": [
                        "logs:CreateLogGroup",
                        "logs:CreateLogStream",
                        "logs:PutLogEvents",
                    ],
                    "Resource": "arn:aws:logs:*:*:*",
                }
            ],
        },
    )
    fn = _create_function_with_retry(ctx, code, role["arn"], {})

    esm_kwargs = dict(
        EventSourceArn=stream["arn"],
        FunctionName=fn["name"],
        StartingPosition="TRIM_HORIZON",
    )
    error_code = None
    try:
        lambda_client.create_event_source_mapping(**esm_kwargs)
    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        error_message = e.response["Error"].get("Message")
    else:
        raise AssertionError(
            "ESM creation succeeded despite missing kinesis stream permissions (overly permissive)"
        )

    assert error_code == "InvalidParameterValueException", (
        f"expected InvalidParameterValueException for missing kinesis stream permissions, "
        f"got {error_code!r}"
    )
    assert error_message == (
        f"Cannot access stream {stream['arn']}. Please ensure the role can perform the "
        "GetRecords, GetShardIterator, DescribeStream, DescribeStreamSummary, ListShards, "
        "and ListStreams Actions on your stream."
    ), error_message

    mappings = lambda_client.list_event_source_mappings(FunctionName=fn["name"])[
        "EventSourceMappings"
    ]
    assert not mappings, (
        f"no event source mapping should exist for {fn['name']!r} after the rejected create, "
        f"found {mappings!r}"
    )

    # Restore: grant the identical permissions the positive control had, then retry the
    # identical call and demand it now succeeds.
    iam = ctx.client("iam")
    iam.put_role_policy(
        RoleName=role["name"],
        PolicyName="kinesis-read",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": _KINESIS_READ_ACTIONS,
                        "Resource": stream["arn"],
                    }
                ],
            }
        ),
    )
    restored_resp = _create_esm_retrying_role_propagation(lambda_client, **esm_kwargs)
    ctx.on_cleanup(
        lambda uuid=restored_resp["UUID"]: lambda_client.delete_event_source_mapping(
            UUID=uuid
        )
    )

    restored_mappings = lambda_client.list_event_source_mappings(
        FunctionName=fn["name"]
    )["EventSourceMappings"]
    assert any(m["UUID"] == restored_resp["UUID"] for m in restored_mappings), (
        f"restored role: expected {restored_resp['UUID']!r} in "
        f"list_event_source_mappings for {fn['name']!r}, got {restored_mappings!r}"
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


def _poll_until(
    probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"
):
    """Poll probe() until predicate(result) is truthy; return the final result (raises on timeout)."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"{description} not met within {timeout_s}s. Last result: {last!r}"
    )


def _wait_for_effect(
    probe, predicate, timeout_s=120.0, interval_s=2.0, description="effect"
):
    """Poll for an async cross-service effect (default 120s — Kinesis/DDB-stream ESMs can need
    60-120s for cold-start + first delivery; fast effects return as soon as the predicate holds)."""
    return _poll_until(
        probe,
        predicate,
        timeout_s=timeout_s,
        interval_s=interval_s,
        description=description,
    )


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
    # No fixed propagation sleep: _create_function_with_retry bounded-retries the
    # "cannot be assumed"/InvalidParameterValue window, and _create_esm_retrying_role_propagation
    # bounded-retries the analogous window for a just-granted stream-read policy.
    return {"name": role_name, "arn": resp["Role"]["Arn"]}


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


def _wait_function_active(ctx, name: str, timeout_s: float = 60) -> None:
    lam = ctx.client("lambda")
    _poll_until(
        lambda: lam.get_function_configuration(FunctionName=name),
        lambda r: r.get("State") == "Active",
        timeout_s=timeout_s,
        interval_s=2.0,
        description=f"Lambda {name} active",
    )


def _create_function_with_retry(
    ctx, handler_code, role_arn, env, timeout=30, memory=128, runtime="python3.12"
) -> dict[str, str]:
    """Create a Lambda, retrying through the IAM role-propagation window, then wait until Active.
    Registers the function's teardown (LIFO-before its role, since the role was registered first)."""
    name = _xname(ctx, "fn")
    lam = ctx.client("lambda")
    # Normalize inline handler source: dedent (checks often embed indented triple-quoted code) and
    # bind to the fixed entrypoint — the Handler is "lambda_function.lambda_handler", but inline code
    # is conventionally written as `def handler(event, context)`. Without a lambda_handler symbol the
    # function fails at runtime with Runtime.HandlerNotFound before any behavior is exercised. Both are
    # no-ops for code that's already column-0 and defines lambda_handler.
    handler_code = textwrap.dedent(handler_code)
    if "def lambda_handler" not in handler_code and "def handler" in handler_code:
        handler_code = handler_code.rstrip() + "\n\nlambda_handler = handler\n"
    zip_buf = BytesIO()
    with zipfile.ZipFile(zip_buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", handler_code)
    kwargs: dict[str, Any] = {
        "FunctionName": name,
        "Runtime": runtime,
        "Role": role_arn,
        "Handler": "lambda_function.lambda_handler",
        "Code": {"ZipFile": zip_buf.getvalue()},
        "Timeout": timeout,
        "MemorySize": memory,
        "Tags": dict(_xsvc_resource_tags()),
    }
    if env:
        kwargs["Environment"] = {"Variables": env}
    deadline = time.monotonic() + 30
    last_err = None
    while time.monotonic() < deadline:
        try:
            resp = lam.create_function(**kwargs)
            ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
            # The function auto-creates /aws/lambda/<name> on first invoke; that log group outlives
            # the function, so delete it too, when it exists: a function that is never invoked has no log group.
            ctx.on_cleanup(lambda: _delete_log_group_if_present(ctx, f"/aws/lambda/{name}"))
            _wait_function_active(ctx, name)
            return {"name": name, "arn": resp["FunctionArn"]}
        except ClientError as e:
            if "cannot be assumed" in str(e) or "InvalidParameterValue" in str(e):
                last_err = e
                time.sleep(3)
                continue
            raise
    raise last_err or RuntimeError(f"Failed to create Lambda {name}")


def _create_lambda(
    ctx,
    handler_code,
    permissions=None,
    env=None,
    timeout=30,
    memory=128,
    runtime="python3.12",
) -> dict[str, str]:
    """Create a Lambda with an execution role scoped to `permissions` (a list of IAM statement
    fragments like [{"Action": ["sqs:SendMessage"], "Resource": queue_arn}]); logs are always
    allowed. Role + function each register their own teardown (function torn down first, LIFO).
    Returns {name,arn}."""
    statements = [
        {
            "Effect": "Allow",
            "Action": [
                "logs:CreateLogGroup",
                "logs:CreateLogStream",
                "logs:PutLogEvents",
            ],
            "Resource": "arn:aws:logs:*:*:*",
        }
    ]
    for perm in permissions or []:
        actions = (
            perm["Action"] if isinstance(perm["Action"], list) else [perm["Action"]]
        )
        resource = (
            perm["Resource"]
            if isinstance(perm["Resource"], list)
            else [perm["Resource"]]
        )
        statements.append({"Effect": "Allow", "Action": actions, "Resource": resource})
    role = _create_role(
        ctx,
        "lambda.amazonaws.com",
        inline_policy={"Version": "2012-10-17", "Statement": statements},
    )
    return _create_function_with_retry(
        ctx, handler_code, role["arn"], env or {}, timeout, memory, runtime
    )


def _delete_log_group_if_present(ctx, log_group_name: str) -> None:
    try:
        ctx.client("logs").delete_log_group(logGroupName=log_group_name)
    except ClientError as e:
        if e.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
