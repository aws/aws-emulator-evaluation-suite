"""lambda-async-retry-exhausted-routes-to-onfailure-destination."""

from __future__ import annotations

import json
import textwrap
import time
import zipfile
from io import BytesIO
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "lambda-async-retry-exhausted-routes-to-onfailure-destination"

GROUP = "error-propagation"

SERVICES = ["lambda", "sqs"]


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """With MaximumRetryAttempts 0, a failing async invoke sends one complete failure record
    (condition RetriesExhausted, invoke count 1, payload, error) to OnFailure and nothing to
    OnSuccess, and a succeeding invoke sends its Success record to OnSuccess only."""
    lam = ctx.client("lambda")
    on_failure = _create_queue(ctx)
    on_success = _create_queue(ctx)

    code = """
    import json

    def handler(event, context):
        if event.get("mode") == "fail":
            raise RuntimeError("poison-event:" + event["marker"])
        return {"echo": event["marker"], "handled": True}
    """
    # The EXECUTION role writes the destination record, so it needs SendMessage on both queues.
    fn = _create_lambda(
        ctx,
        code,
        permissions=[
            {
                "Action": ["sqs:SendMessage"],
                "Resource": [on_failure["arn"], on_success["arn"]],
            }
        ],
    )

    lam.put_function_event_invoke_config(
        FunctionName=fn["name"],
        MaximumRetryAttempts=0,
        MaximumEventAgeInSeconds=60,
        DestinationConfig={
            "OnFailure": {"Destination": on_failure["arn"]},
            "OnSuccess": {"Destination": on_success["arn"]},
        },
    )
    ctx.on_cleanup(
        lambda: lam.delete_function_event_invoke_config(FunctionName=fn["name"])
    )
    cfg = lam.get_function_event_invoke_config(FunctionName=fn["name"])
    assert cfg["MaximumRetryAttempts"] == 0, (
        f"retry config not stored: {cfg.get('MaximumRetryAttempts')!r}"
    )
    assert (
        cfg["DestinationConfig"]["OnFailure"]["Destination"] == on_failure["arn"]
    ), f"OnFailure destination not stored: {cfg['DestinationConfig']}"

    # --- failure path -----------------------------------------------------------------
    fail_marker = _xname(ctx, "fail")
    fail_payload = {"mode": "fail", "marker": fail_marker}
    resp = lam.invoke(
        FunctionName=fn["name"],
        InvocationType="Event",
        Payload=json.dumps(fail_payload).encode(),
    )
    assert resp["StatusCode"] == 202, (
        f"async invoke must return 202 Accepted, got {resp['StatusCode']}"
    )

    # 180s: async queueing + the (zero) retry window + destination delivery.
    record = _wait_for_messages(ctx, on_failure["url"], expected_count=1, timeout_s=180)[0][
        "body"
    ]
    assert isinstance(record, dict), f"failure record is not JSON: {record!r}"
    assert record.get("version") == "1.0", (
        f"async destination record version wrong: {record.get('version')!r}"
    )
    rc = record.get("requestContext", {})
    assert rc.get("condition") == "RetriesExhausted", (
        f"failure condition wrong: {rc.get('condition')!r} (expected RetriesExhausted)"
    )
    # The whole point of MaximumRetryAttempts=0: exactly one attempt, no silent extra retries.
    assert rc.get("approximateInvokeCount") == 1, (
        f"MaximumRetryAttempts=0 must yield approximateInvokeCount 1, got "
        f"{rc.get('approximateInvokeCount')!r}"
    )
    assert fn["arn"] in rc.get("functionArn", ""), (
        f"failure record functionArn wrong: {rc.get('functionArn')!r}"
    )
    assert record.get("requestPayload") == fail_payload, (
        f"requestPayload not preserved: {record.get('requestPayload')!r}"
    )
    assert record.get("responseContext", {}).get("functionError") == "Unhandled", (
        f"responseContext.functionError wrong: {record.get('responseContext')!r}"
    )
    rp = record.get("responsePayload", {})
    assert rp.get("errorType") == "RuntimeError", (
        f"responsePayload.errorType wrong: {rp!r}"
    )
    assert rp.get("errorMessage") == f"poison-event:{fail_marker}", (
        f"responsePayload.errorMessage lost the marker: {rp!r}"
    )

    # Effect-absent half: a FAILED invoke must produce nothing on the success destination.
    stray = _drain_queue(ctx, on_success["url"], window_s=12.0)
    assert not [b for b in stray if fail_marker in b], (
        f"failed invoke also wrote to the OnSuccess destination: {stray}"
    )

    # --- control: the success path still routes, and routes the other way -------------
    ok_marker = _xname(ctx, "ok")
    ok_payload = {"mode": "ok", "marker": ok_marker}
    lam.invoke(
        FunctionName=fn["name"],
        InvocationType="Event",
        Payload=json.dumps(ok_payload).encode(),
    )
    ok_record = _wait_for_messages(ctx, on_success["url"], expected_count=1, timeout_s=180)[
        0
    ]["body"]
    assert ok_record.get("requestContext", {}).get("condition") == "Success", (
        f"success condition wrong: {ok_record.get('requestContext')!r}"
    )
    assert ok_record.get("responsePayload") == {"echo": ok_marker, "handled": True}, (
        f"success responsePayload is not the handler return value: "
        f"{ok_record.get('responsePayload')!r}"
    )
    assert "functionError" not in ok_record.get("responseContext", {}), (
        f"success record must not carry functionError: {ok_record.get('responseContext')!r}"
    )
    residue = _drain_queue(ctx, on_failure["url"], window_s=12.0)
    assert not [b for b in residue if ok_marker in b], (
        f"successful invoke also wrote to the OnFailure destination: {residue}"
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


def _drain_queue(ctx, queue_url, *, window_s=12.0):
    """Receive-and-delete everything visible on a queue for a bounded window; return raw bodies.

    Used for the effect-ABSENT half of a delivery assertion: an empty return over a bounded
    window is the observable "nothing was delivered", and draining first gives the positive
    half a queue whose contents are attributable to exactly one publish.
    """
    sqs = ctx.client("sqs")
    bodies: list[str] = []
    deadline = time.monotonic() + window_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=2
        )
        msgs = resp.get("Messages", [])
        for msg in msgs:
            bodies.append(msg["Body"])
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
    return bodies


def _wait_for_messages(ctx, queue_url, expected_count=1, timeout_s=60.0, delete=True):
    """Poll SQS until expected_count messages arrive; return them (raises on timeout)."""
    sqs = ctx.client("sqs")
    messages: list[dict[str, Any]] = []
    deadline = time.monotonic() + timeout_s
    while len(messages) < expected_count and time.monotonic() < deadline:
        remaining = max(1, int(deadline - time.monotonic()))
        resp = sqs.receive_message(
            QueueUrl=queue_url,
            MaxNumberOfMessages=min(10, expected_count - len(messages)),
            WaitTimeSeconds=min(5, remaining),
            MessageAttributeNames=["All"],
        )
        for msg in resp.get("Messages", []):
            try:
                body = json.loads(msg["Body"])
            except (json.JSONDecodeError, ValueError):
                body = msg["Body"]
            messages.append(
                {
                    "body": body,
                    "message_id": msg["MessageId"],
                    "receipt_handle": msg["ReceiptHandle"],
                    "attributes": msg.get("MessageAttributes", {}),
                }
            )
            if delete:
                sqs.delete_message(
                    QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"]
                )
    if len(messages) < expected_count:
        raise AssertionError(
            f"Expected {expected_count} messages, got {len(messages)} within {timeout_s}s"
        )
    return messages


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
            # function deletion, so it is deleted here.
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


def _create_queue(ctx, fifo: bool = False, **attrs: str) -> dict[str, str]:
    """Create an SQS queue (registers delete_queue teardown). Returns {name,url,arn}."""
    base = _xname(ctx, "q")
    name = f"{base}.fifo" if fifo else base
    sqs = ctx.client("sqs")
    create_attrs = dict(attrs)
    if fifo:
        create_attrs["FifoQueue"] = "true"
    resp = sqs.create_queue(
        QueueName=name, Attributes=create_attrs, tags=_xsvc_resource_tags()
    )
    url = resp["QueueUrl"]
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])[
        "Attributes"
    ]["QueueArn"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    return {"name": name, "url": url, "arn": arn}


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
