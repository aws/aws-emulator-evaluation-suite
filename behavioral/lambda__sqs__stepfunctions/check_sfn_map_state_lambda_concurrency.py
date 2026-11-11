"""sfn-map-state-lambda-concurrency."""

from __future__ import annotations

import json
import textwrap
import time
import zipfile
from io import BytesIO
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sfn-map-state-lambda-concurrency"

GROUP = "event-propagation"

SERVICES = ["lambda", "stepfunctions", "sqs"]

_TRUST_RACE_MARKERS = (
    "not authorized to assume",
    "cannot be assumed",
    "is not authorized to perform: sts:AssumeRole",
)


def _run_sfn_until_trust_propagated(
    sfn, sm_arn: str, input_str: str, max_attempts: int = 8
):
    """Start an execution, retrying only while it fails on the IAM-trust race.

    Returns the terminal describe_execution dict. Raises AssertionError only if the
    trust never propagates within the budget (a genuine, reportable condition).
    """
    desc = None
    for attempt in range(max_attempts):
        execution = sfn.start_execution(stateMachineArn=sm_arn, input=input_str)
        exec_arn = execution["executionArn"]
        desc = _poll_until(
            lambda: sfn.describe_execution(executionArn=exec_arn),
            lambda d: d["status"] in ("SUCCEEDED", "FAILED", "TIMED_OUT", "ABORTED"),
            timeout_s=30,
            interval_s=3,
        )
        if desc["status"] != "FAILED":
            return desc
        cause = (desc.get("cause") or "") + (desc.get("error") or "")
        if not any(m in cause for m in _TRUST_RACE_MARKERS):
            # A real failure (not the trust race) — return it for the check to assert on.
            return desc
        # Trust race: back off and retry with a fresh execution.
        time.sleep(10 + attempt * 5)
    raise AssertionError(
        f"Step Functions role trust did not propagate after {max_attempts} attempts "
        f"(last cause: {desc.get('cause') if desc else 'n/a'})"
    )


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """SFN Map state with MaxConcurrency=2 runs Lambda invocations in parallel, bounded by the
    cap: an independent SQS side-channel records each invocation's start/end so the check can
    measure real overlap, since DescribeExecution reports only the aggregate result."""
    sqs = ctx.client("sqs")
    queue_name = ctx.unique_name("sfn-map-concurrency-")
    queue_url = sqs.create_queue(QueueName=queue_name, tags=_xsvc_resource_tags())["QueueUrl"]
    queue_arn = sqs.get_queue_attributes(
        QueueUrl=queue_url, AttributeNames=["QueueArn"]
    )["Attributes"]["QueueArn"]
    ctx.on_cleanup(lambda: ctx.client("sqs").delete_queue(QueueUrl=queue_url))

    handler_code = """
import json
import os
import time

import boto3


def lambda_handler(event, context):
    sqs = boto3.client("sqs", region_name=os.environ["AWS_REGION"])
    queue_url = os.environ["QUEUE_URL"]
    item = event.get("item", 0)
    start = time.time()
    sqs.send_message(
        QueueUrl=queue_url,
        MessageBody=json.dumps({"item": item, "event": "start", "t": start}),
    )
    time.sleep(5)
    end = time.time()
    sqs.send_message(
        QueueUrl=queue_url,
        MessageBody=json.dumps({"item": item, "event": "end", "t": end}),
    )
    return {'result': item * 2}
"""
    fn = _create_lambda(
        ctx,
        handler_code=handler_code,
        permissions=[{"Action": ["sqs:SendMessage"], "Resource": queue_arn}],
        env={"QUEUE_URL": queue_url},
        timeout=30,
    )

    sfn = ctx.client("stepfunctions")
    iam = ctx.client("iam")

    role_name = ctx.unique_name("sfn-map-role-")
    trust = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "states.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
    )
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=trust)
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: ctx.client("iam").delete_role(RoleName=role_name))

    policy_doc = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "lambda:InvokeFunction",
                    "Resource": fn["arn"],
                }
            ],
        }
    )
    iam.put_role_policy(
        RoleName=role_name, PolicyName="map-pol", PolicyDocument=policy_doc
    )
    # Wait for IAM policy to be readable
    _poll_until(
        lambda: iam.get_role_policy(RoleName=role_name, PolicyName="map-pol"),
        lambda r: "PolicyDocument" in r,
        timeout_s=30,
        interval_s=2,
    )

    sm_name = ctx.unique_name("sm-map-")
    definition = json.dumps(
        {
            "StartAt": "MapState",
            "States": {
                "MapState": {
                    "Type": "Map",
                    "ItemsPath": "$.items",
                    "MaxConcurrency": 2,
                    "Parameters": {"item.$": "$$.Map.Item.Value"},
                    "Iterator": {
                        "StartAt": "InvokeLambda",
                        "States": {
                            "InvokeLambda": {
                                "Type": "Task",
                                "Resource": "arn:aws:states:::lambda:invoke",
                                "Parameters": {
                                    "FunctionName": fn["arn"],
                                    "Payload.$": "$",
                                },
                                "ResultSelector": {"result.$": "$.Payload.result"},
                                "End": True,
                            }
                        },
                    },
                    "End": True,
                }
            },
        }
    )
    sm = sfn.create_state_machine(name=sm_name, definition=definition, roleArn=role_arn)
    sm_arn = sm["stateMachineArn"]
    ctx.on_cleanup(
        lambda: ctx.client("stepfunctions").delete_state_machine(stateMachineArn=sm_arn)
    )

    desc = _run_sfn_until_trust_propagated(
        sfn, sm_arn, json.dumps({"items": [1, 2, 3]})
    )

    assert desc["status"] == "SUCCEEDED", f"Expected SUCCEEDED, got: {desc['status']}"
    output = json.loads(desc["output"])
    results = [item["result"] for item in output]
    assert sorted(results) == [2, 4, 6], f"Expected [2,4,6], got: {sorted(results)}"

    raw_messages: list[dict] = []
    deadline = time.monotonic() + 30
    while len(raw_messages) < 6 and time.monotonic() < deadline:
        resp = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5
        )
        for m in resp.get("Messages", []):
            raw_messages.append(json.loads(m["Body"]))
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=m["ReceiptHandle"])
    assert len(raw_messages) == 6, (
        f"Expected 6 concurrency-probe messages (3 items x start+end), "
        f"got {len(raw_messages)}: {raw_messages}"
    )

    starts = {m["item"]: m["t"] for m in raw_messages if m["event"] == "start"}
    ends = {m["item"]: m["t"] for m in raw_messages if m["event"] == "end"}
    assert set(starts) == set(ends) == {1, 2, 3}, (
        f"Expected start/end pairs for items 1,2,3, got starts={starts} ends={ends}"
    )

    events = sorted(
        [(starts[i], 1) for i in starts] + [(ends[i], -1) for i in ends]
    )
    running = 0
    max_running = 0
    for _, delta in events:
        running += delta
        max_running = max(max_running, running)

    assert max_running >= 2, (
        f"Expected at least 2 Lambda invocations to run concurrently under "
        f"MaxConcurrency=2, but the max observed overlap was {max_running}"
    )
    assert max_running <= 2, (
        f"MaxConcurrency=2 was violated: observed {max_running} concurrent "
        f"Lambda invocations (starts={starts}, ends={ends})"
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
    # IAM role trust/permission propagation is eventually consistent; no unconditional wait here —
    # _create_function_with_retry below retries create_function through the propagation window.
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
            # The function auto-creates /aws/lambda/<name> on first invoke; that log group survives
            # function deletion, so delete it
            # too (best-effort — on_cleanup swallows if it was never created).
            ctx.on_cleanup(
                lambda: ctx.client("logs").delete_log_group(
                    logGroupName=f"/aws/lambda/{name}"
                )
            )
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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
