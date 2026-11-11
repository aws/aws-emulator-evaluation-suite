"""lambda-role-without-events-putevents-permission-denied."""

from __future__ import annotations

import json
import textwrap
import time
import uuid
import zipfile
from io import BytesIO
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "lambda-role-without-events-putevents-permission-denied"

GROUP = "overly-permissive"

SERVICES = ["events", "lambda", "sqs"]


@tags("axis:rejection", "cap:c3", "cap:c7", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Lambda's events:PutEvents call succeeds with an IAM grant, is denied with
    AccessDeniedException and its exact message once the grant is revoked on the same role, and
    succeeds again when restored; delivery and its absence are read at the rule's SQS target."""
    events = ctx.client("events")
    sqs = ctx.client("sqs")

    source = _xname(ctx, "src")
    queue_url = sqs.create_queue(
        QueueName=_xname(ctx, "queue"), tags=_xsvc_resource_tags()
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=queue_url))
    queue_arn = sqs.get_queue_attributes(
        QueueUrl=queue_url, AttributeNames=["QueueArn"]
    )["Attributes"]["QueueArn"]

    rule_name = _xname(ctx, "rule")
    rule_arn = events.put_rule(
        Name=rule_name,
        EventPattern=json.dumps({"source": [source]}),
        State="ENABLED",
        Tags=_xsvc_tags_kv(),
    )["RuleArn"]
    ctx.on_cleanup(lambda: events.delete_rule(Name=rule_name))

    sqs.set_queue_attributes(
        QueueUrl=queue_url,
        Attributes={
            "Policy": json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {"Service": "events.amazonaws.com"},
                            "Action": "sqs:SendMessage",
                            "Resource": queue_arn,
                            "Condition": {"ArnEquals": {"aws:SourceArn": rule_arn}},
                        }
                    ],
                }
            )
        },
    )
    events.put_targets(Rule=rule_name, Targets=[{"Id": "queue-target", "Arn": queue_arn}])
    ctx.on_cleanup(lambda: events.remove_targets(Rule=rule_name, Ids=["queue-target"]))

    code = f'''
import json

import boto3


def lambda_handler(event, context):
    client = boto3.client("events")
    try:
        client.put_events(
            Entries=[{{
                "Source": "{source}",
                "DetailType": "x",
                "Detail": json.dumps({{"nonce": event.get("nonce")}}),
            }}]
        )
        return {{"ok": True}}
    except Exception as e:
        return {{"ok": False, "error": str(e)}}
'''

    role = _create_role(ctx, "lambda.amazonaws.com", inline_policy=_logs_only_policy())
    fn = _create_function_with_retry(ctx, code, role["arn"], {})

    # Each invoke carries a fresh nonce so a message can be traced to the call that produced it.
    # EventBridge -> SQS delivery is at-least-once, and IAM policy changes are eventually
    # consistent, so a call made right after a grant/revoke can transiently still see the old
    # state, and any successful call's message can legitimately be redelivered later. Tracking
    # nonces lets the absence check tell "a harmless duplicate of a call we know succeeded" apart
    # from "a call made under denial that leaked anyway" -- the only outcome that's a real defect.
    succeeded_nonces: set[str] = set()
    arrived_nonces: set[str] = set()

    def _invoke_once() -> tuple[str, dict[str, Any]]:
        nonce = uuid.uuid4().hex
        result = _invoke_lambda(ctx, fn["name"], {"nonce": nonce})
        assert result.get("error") is None, f"handler should not fault: {result}"
        if result["payload"]["ok"] is True:
            succeeded_nonces.add(nonce)
        return nonce, result

    def _pump(wait_s: int = 5) -> list[str]:
        seen = _drain_queue(sqs, queue_url, wait_s=wait_s)
        arrived_nonces.update(seen)
        return seen

    # --- positive control: grant the permission, the call succeeds, and the event is
    # independently observed arriving at the SQS target wired to the rule.
    _set_events_permission(ctx, role["name"], granted=True)
    positive_nonce, result = _poll_until(
        _invoke_once,
        lambda r: r[1]["payload"]["ok"] is True,
        timeout_s=30.0,
        interval_s=2.0,
        description="positive control: events:PutEvents to succeed with the IAM grant present",
    )
    started = time.monotonic()
    _poll_until(
        _pump,
        lambda _seen: positive_nonce in arrived_nonces,
        timeout_s=30.0,
        interval_s=1.0,
        description="event delivered to the SQS target",
    )
    positive_latency_s = time.monotonic() - started

    # --- break exactly one thing: revoke the grant on the SAME role, and assert the SPECIFIC
    # denial on the identical call.
    _set_events_permission(ctx, role["name"], granted=False)
    _denied_nonce, result2 = _poll_until(
        _invoke_once,
        lambda r: r[1]["payload"]["ok"] is False,
        timeout_s=30.0,
        interval_s=2.0,
        description="events:PutEvents to be denied once the grant is revoked",
    )
    expected = (
        "An error occurred (AccessDeniedException) when calling the PutEvents operation: "
        f"User: arn:aws:sts::{ctx.account}:assumed-role/{role['name']}/{fn['name']} is not authorized "
        f"to perform: events:PutEvents on resource: arn:aws:events:{ctx.region}:{ctx.account}:"
        "event-bus/default because no identity-based policy allows the events:PutEvents action"
    )
    assert result2["payload"]["error"] == expected, (
        f"expected {expected!r}, got: {result2['payload']['error']!r}"
    )

    # --- absence held for a window calibrated off the positive control's own latency, read by
    # nonce on every message the window receives. A message whose nonce is already in
    # succeeded_nonces is a known-benign duplicate; anything else is a real leak while the grant
    # was revoked.
    _assert_no_unexpected_delivery(
        sqs,
        queue_url,
        succeeded_nonces,
        arrived_nonces,
        window_s=min(max(3 * positive_latency_s, 15.0), 60.0),
    )

    # --- restore: re-grant the identical permission on the SAME role, and the identical call
    # succeeds again, with delivery re-confirmed at the destination.
    _set_events_permission(ctx, role["name"], granted=True)
    restore_nonce, result3 = _poll_until(
        _invoke_once,
        lambda r: r[1]["payload"]["ok"] is True,
        timeout_s=30.0,
        interval_s=2.0,
        description="events:PutEvents to succeed again once the grant is restored",
    )
    _poll_until(
        _pump,
        lambda _seen: restore_nonce in arrived_nonces,
        timeout_s=30.0,
        interval_s=1.0,
        description="event delivered to the SQS target after the grant is restored",
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


def _delete_log_group_if_present(ctx, log_group: str) -> None:
    try:
        ctx.client("logs").delete_log_group(logGroupName=log_group)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
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
            # The function creates /aws/lambda/<name> on first invoke and the group outlives the
            # function, so delete it too; a function never invoked has no log group to delete.
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


def _logs_only_policy() -> dict[str, Any]:
    return {
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
    }


def _set_events_permission(ctx, role_name: str, *, granted: bool) -> None:
    """Overwrite the role's inline policy in place: logs only, plus events:PutEvents when granted.
    Same policy name each time, so this is a change on the SAME role, not a new role."""
    statements = list(_logs_only_policy()["Statement"])
    if granted:
        statements.append(
            {"Effect": "Allow", "Action": "events:PutEvents", "Resource": "*"}
        )
    ctx.client("iam").put_role_policy(
        RoleName=role_name,
        PolicyName="inline",
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
    )


def _drain_queue(sqs, queue_url: str, wait_s: int = 5) -> list[str]:
    """Receive and delete whatever is currently on the queue; return the nonces seen."""
    resp = sqs.receive_message(
        QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=wait_s
    )
    seen = []
    for msg in resp.get("Messages", []):
        nonce = json.loads(msg["Body"])["detail"]["nonce"]
        sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
        seen.append(nonce)
    return seen


def _assert_no_unexpected_delivery(
    sqs,
    queue_url: str,
    succeeded_nonces: set[str],
    arrived_nonces: set[str],
    window_s: float,
) -> None:
    """Hold absence for window_s. A duplicate of a call already known to have succeeded is
    tolerated (EventBridge -> SQS is at-least-once); any other arrival means a denied call's
    event leaked through and is a real failure. No exact queue-depth read follows: a tolerated
    duplicate keeps ApproximateNumberOfMessages above 0, and SQS documents the counter as
    eventually consistent (GetQueueAttributes)."""
    deadline = time.monotonic() + window_s
    while time.monotonic() < deadline:
        seen = _drain_queue(sqs, queue_url, wait_s=5)
        arrived_nonces.update(seen)
        unexpected = [n for n in seen if n not in succeeded_nonces]
        assert not unexpected, (
            f"denied call must not deliver anything, got unexpected nonces: {unexpected}"
        )


def _invoke_lambda(ctx, name: str, payload: dict | None = None) -> dict[str, Any]:
    """Invoke a Lambda synchronously; return {status_code[, error], payload|payload_raw}."""
    resp = ctx.client("lambda").invoke(
        FunctionName=name,
        InvocationType="RequestResponse",
        Payload=json.dumps(payload or {}).encode(),
    )
    body = resp["Payload"].read()
    result: dict[str, Any] = {"status_code": resp["StatusCode"]}
    if resp.get("FunctionError"):
        result["error"] = resp["FunctionError"]
    try:
        result["payload"] = json.loads(body)
    except (json.JSONDecodeError, ValueError):
        result["payload_raw"] = body.decode("utf-8", errors="replace")
    return result


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
