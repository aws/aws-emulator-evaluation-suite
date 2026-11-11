"""sfn-lambda-task-event-invocation-returns-202-and-the-function-delivers-to-sqs."""

from __future__ import annotations

import json
import textwrap
import time
import zipfile
from io import BytesIO
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sfn-lambda-task-event-invocation-returns-202-and-the-function-delivers-to-sqs"

GROUP = "event-propagation"

SERVICES = ["lambda", "stepfunctions", "sqs"]

_TRUST_RACE_MARKERS = (
    "not authorized to assume",
    "cannot be assumed",
    "is not authorized to perform: sts:AssumeRole",
)


def _run_sfn_until_trust_propagated(sfn, sm_arn: str, input_str: str, budget_s: float = 40.0):
    """Start an execution, retrying only while it fails on the IAM-trust race.

    Returns the terminal describe_execution dict. Within ``budget_s`` in total; on expiry it raises
    with the last execution's status and cause.
    """
    deadline = time.monotonic() + budget_s
    while True:
        execution = sfn.start_execution(stateMachineArn=sm_arn, input=input_str)
        exec_arn = execution["executionArn"]
        desc = _poll_until(
            lambda arn=exec_arn: sfn.describe_execution(executionArn=arn),
            lambda d: d["status"] in ("SUCCEEDED", "FAILED", "TIMED_OUT", "ABORTED"),
            timeout_s=max(1.0, deadline - time.monotonic()),
            interval_s=2,
            description="the execution reaches a terminal status",
        )
        if desc["status"] != "FAILED":
            return desc
        cause = (desc.get("cause") or "") + (desc.get("error") or "")
        if not any(m in cause for m in _TRUST_RACE_MARKERS):
            # A real failure (not the trust race) is returned for the check to assert on.
            return desc
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"the Step Functions role was still not assumable after {budget_s}s: the last execution "
                f"ended {desc['status']} with error {desc.get('error')!r}, cause {desc.get('cause')!r}"
            )
        # Trust race: back off briefly and retry with a fresh execution.
        time.sleep(min(5.0, max(0.0, deadline - time.monotonic())))


def _receive_until(sqs, url: str, by_id: dict, done, timeout_s: float, what: str) -> None:
    """Receive and delete messages into ``by_id`` (MessageId -> body) until ``done(by_id)`` holds.

    A standard queue is at-least-once, so copies of a message collapse onto its MessageId. On expiry
    it raises with the distinct messages seen so far.
    """
    deadline = time.monotonic() + timeout_s
    while not done(by_id):
        assert time.monotonic() < deadline, f"{what} within {timeout_s}s; the queue delivered {by_id!r}"
        msgs = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=5).get("Messages", [])
        for m in msgs:
            sqs.delete_message(QueueUrl=url, ReceiptHandle=m["ReceiptHandle"])
            by_id.setdefault(m["MessageId"], json.loads(m["Body"]))


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """A lambda:invoke Task with InvocationType Event returns StatusCode 202 with a null Payload as
    its result, and the function still runs: the message it computes from the Task's payload, the
    square of the input value with the execution's marker, arrives at the SQS queue."""
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=_xname(ctx, "q"), tags=_xsvc_resource_tags())["QueueUrl"]
    ctx.on_cleanup(lambda: _delete_queue(sqs, url))
    queue_arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    handler_code = """
import json
import boto3


def lambda_handler(event, context):
    body = {"square": event["value"] ** 2, "marker": event["marker"]}
    sent = boto3.client("sqs").send_message(QueueUrl=event["queue_url"], MessageBody=json.dumps(body))
    return dict(body, message_id=sent["MessageId"])
"""
    fn = _create_lambda(ctx, handler_code=handler_code,
                        permissions=[{"Action": ["sqs:SendMessage"], "Resource": queue_arn}])
    lam = ctx.client("lambda")
    # The function's SendMessage grant is eventually consistent: a synchronous probe invoke, retried
    # until it succeeds, proves it before the asynchronous path depends on it.
    deadline = time.monotonic() + 40
    while True:
        resp = lam.invoke(FunctionName=fn["name"], Payload=json.dumps(
            {"value": 0, "marker": "probe", "queue_url": url}).encode())
        body = resp["Payload"].read()
        if not resp.get("FunctionError"):
            probe_id = json.loads(body)["message_id"]
            break
        assert time.monotonic() < deadline, (
            f"the function's probe SendMessage still failed after 40s: last FunctionError "
            f"{resp.get('FunctionError')!r}, payload {body[:300]!r}")
        time.sleep(5)
    by_id: dict = {}
    _receive_until(sqs, url, by_id, lambda seen: probe_id in seen, 40,
                   "the probe invoke's message did not arrive")
    probe = {probe_id: {"square": 0, "marker": "probe"}}
    assert by_id == probe, f"after the probe invoke the queue delivered {by_id!r}, expected only {probe!r}"

    sfn = ctx.client("stepfunctions")
    role_arn = _states_role(ctx, fn["arn"])
    partition = role_arn.split(":")[1]
    definition = {
        "StartAt": "Fire",
        "States": {
            "Fire": {
                "Type": "Task",
                "Resource": f"arn:{partition}:states:::lambda:invoke",
                "Parameters": {
                    "FunctionName": fn["arn"],
                    "InvocationType": "Event",
                    "Payload": {"value.$": "$.value", "marker.$": "$.marker", "queue_url": url},
                },
                "ResultSelector": {"status.$": "$.StatusCode", "payload.$": "$.Payload"},
                "End": True,
            }
        },
    }
    sm_arn = _state_machine(ctx, sfn, definition, role_arn)
    marker = ctx.unique_name("m-")
    desc = _run_sfn_until_trust_propagated(sfn, sm_arn, json.dumps({"value": 37, "marker": marker}))
    assert desc["status"] == "SUCCEEDED", f"Expected SUCCEEDED, got {desc['status']}: {desc.get('cause')!r}"
    output = json.loads(desc["output"])
    assert output == {"status": 202, "payload": None}, (
        f"an Event Task's result: expected StatusCode 202 and a null Payload, got {output!r}")

    _receive_until(sqs, url, by_id, lambda seen: any(b.get("marker") == marker for b in seen.values()), 40,
                   f"no message with marker {marker!r} reached the queue")
    # An Event invoke is at-least-once too: a repeat run sends another message with the same body.
    # Every distinct message is the probe or one this execution's function computed.
    want = {"square": 1369, "marker": marker}
    stray = {mid: b for mid, b in by_id.items() if mid != probe_id and b != want}
    assert not stray, f"the queue delivered messages this check did not send: {stray!r}"
    assert by_id.get(probe_id, probe[probe_id]) == probe[probe_id], f"the probe message changed: {by_id!r}"


def _delete_queue(sqs, url: str) -> None:
    try:
        sqs.delete_queue(QueueUrl=url)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("AWS.SimpleQueueService.NonExistentQueue", "QueueDoesNotExist"):
            raise




def _states_role(ctx, fn_arn: str) -> str:
    """A Step Functions role allowed to invoke exactly ``fn_arn``; returns its ARN."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sfn-role-")
    trust = {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Principal": {"Service": "states.amazonaws.com"}, "Action": "sts:AssumeRole"}]}
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust),
                               Tags=_xsvc_tags_kv())["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    policy = {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Action": "lambda:InvokeFunction", "Resource": fn_arn}]}
    iam.put_role_policy(RoleName=role_name, PolicyName="invoke", PolicyDocument=json.dumps(policy))
    return role_arn


def _state_machine(ctx, sfn, definition: dict, role_arn: str) -> str:
    sm_arn = sfn.create_state_machine(
        name=ctx.unique_name("sm-invoke-"), definition=json.dumps(definition), roleArn=role_arn,
        tags=[{"key": k, "value": v} for k, v in _xsvc_resource_tags().items()],
    )["stateMachineArn"]
    ctx.on_cleanup(lambda: _ignore_missing_state_machine(sfn, sm_arn))
    return sm_arn


def _ignore_missing_state_machine(sfn, sm_arn: str) -> None:
    try:
        sfn.delete_state_machine(stateMachineArn=sm_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "StateMachineDoesNotExist":
            raise


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
    probe, predicate, *, timeout_s=40, interval_s=1.0, description="condition"
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
    # Role propagation is absorbed by the bounded retry in _create_function_with_retry.
    return {"name": role_name, "arn": resp["Role"]["Arn"]}


def _delete_log_group(ctx, name: str) -> None:
    """Delete a log group; only one that does not exist (ResourceNotFoundException) is tolerated."""
    try:
        ctx.client("logs").delete_log_group(logGroupName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _delete_role(ctx, role_name: str) -> None:
    """IAM roles need every attached + inline policy removed before deletion; DeleteConflict is
    retried while IAM catches up with the removals, and only an already-gone role (NoSuchEntity)
    is tolerated."""
    iam = ctx.client("iam")
    deadline = time.monotonic() + 40
    while True:
        try:
            for p in iam.list_attached_role_policies(RoleName=role_name).get(
                "AttachedPolicies", []
            ):
                iam.detach_role_policy(RoleName=role_name, PolicyArn=p["PolicyArn"])
            for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
                iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
            iam.delete_role(RoleName=role_name)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "NoSuchEntity":
                return
            if code != "DeleteConflict" or time.monotonic() >= deadline:
                raise
            time.sleep(3)


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
    # Inline sources are dedented and bound to the fixed lambda_function.lambda_handler entrypoint.
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
            # The first log line creates /aws/lambda/<name>, which outlives the function.
            ctx.on_cleanup(lambda: _delete_log_group(ctx, f"/aws/lambda/{name}"))
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
    partition = ctx.client("sts").get_caller_identity()["Arn"].split(":")[1]
    statements = [
        {
            "Effect": "Allow",
            "Action": [
                "logs:CreateLogGroup",
                "logs:CreateLogStream",
                "logs:PutLogEvents",
            ],
            "Resource": f"arn:{partition}:logs:*:*:*",
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
