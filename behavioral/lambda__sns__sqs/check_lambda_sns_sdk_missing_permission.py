"""lambda-sns-sdk-missing-permission."""

from __future__ import annotations

import json
import textwrap
import time
import zipfile
from io import BytesIO
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "lambda-sns-sdk-missing-permission"

GROUP = "overly-permissive"

SERVICES = ["lambda", "sns", "sqs"]


_CODE = '''
import boto3
sns = boto3.client("sns")
def lambda_handler(event, context):
    try:
        sns.publish(TopicArn=event["topic_arn"], Message=event["message"])
        return {"ok": True}
    except Exception as e:
        code = getattr(e, "response", {}).get("Error", {}).get("Code", type(e).__name__)
        message = getattr(e, "response", {}).get("Error", {}).get("Message")
        return {"ok": False, "error_code": code, "message": message}
'''


@tags("axis:rejection", "cap:c3", "cap:c7", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Lambda role without sns:Publish gets AuthorizationError, its message never reaches the
    subscribed queue and the queue polls to 0 visible; an otherwise-identical role with
    sns:Publish delivers its message (positive control, same wiring)."""
    topic = _create_topic(ctx)
    queue = _create_queue_subscribed(ctx, topic)

    # --- positive control: role has sns:Publish. Also calibrates the delivery latency
    # used below to bound how long absence must be held for the negative case. ---
    allow_fn = _create_lambda(
        ctx, _CODE, permissions=[{"Action": "sns:Publish", "Resource": topic["arn"]}]
    )
    marker_allowed = ctx.unique_name("allowed-")
    t0 = time.monotonic()
    allowed = _invoke_lambda(
        ctx, allow_fn["name"], {"topic_arn": topic["arn"], "message": marker_allowed}
    )
    allowed_payload = allowed.get("payload") or {}
    assert allowed_payload.get("ok") is True, (
        f"positive control failed: role with sns:Publish could not publish: {allowed}"
    )
    delivered = _poll_for_message(ctx, queue["url"], marker_allowed, timeout_s=60.0)
    latency_s = time.monotonic() - t0
    assert delivered, (
        f"positive control's message never reached the subscribed queue: {allowed}"
    )

    # --- negative: role has no sns:Publish ---
    deny_fn = _create_lambda(ctx, _CODE, permissions=[])
    marker_denied = ctx.unique_name("denied-")
    denied = _invoke_lambda(
        ctx, deny_fn["name"], {"topic_arn": topic["arn"], "message": marker_denied}
    )
    denied_payload = denied.get("payload") or {}
    assert denied_payload.get("ok") is False, (
        f"Lambda succeeded publishing to SNS without an IAM permission grant: {denied}"
    )
    # SNS signals authorization failures with "AuthorizationError" (not "AccessDenied").
    assert denied_payload.get("error_code") == "AuthorizationError", (
        f"expected sns:Publish to be denied with AuthorizationError, got: {denied}"
    )
    role_arn = ctx.client("lambda").get_function_configuration(FunctionName=deny_fn["name"])["Role"]
    principal = (
        f"arn:aws:sts::{topic['arn'].split(':')[4]}:assumed-role/{role_arn.rsplit('/', 1)[1]}/{deny_fn['name']}"
    )
    expected_message = (
        f"User: {principal} is not authorized to perform: SNS:Publish on resource: {topic['arn']} "
        "because no identity-based policy allows the SNS:Publish action"
    )
    assert denied_payload.get("message") == expected_message, (
        f"expected {expected_message!r}, got {denied_payload.get('message')!r}"
    )

    # Effect absent at the destination, held for >= 3x the positive control's own latency
    # and confirmed on a second independent observable, so a correct-but-slower target is
    # never mistaken for one that blocked delivery.
    window_s = max(3.0 * latency_s, 15.0)
    absent = not _poll_for_message(ctx, queue["url"], marker_denied, timeout_s=window_s)
    assert absent, (
        f"message published without sns:Publish permission still reached the queue: {denied}"
    )
    _poll_queue_counters(ctx, ctx.client("sqs"), queue["url"], {"ApproximateNumberOfMessages": "0"})


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
    # Dedent the inline source and alias `handler` to `lambda_handler`, the fixed entrypoint;
    # without that symbol the function fails with Runtime.HandlerNotFound.
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
    # No fixed pre-sleep for IAM trust/permission propagation: this bounded retry,
    # keyed on the assume-role error the emulator and real AWS both raise while propagation
    # is still in flight, is the only wait.
    deadline = time.monotonic() + 60
    last_err = None
    while time.monotonic() < deadline:
        try:
            resp = lam.create_function(**kwargs)
            ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
            # The function auto-creates /aws/lambda/<name> on first invoke; that log group survives
            # function deletion, so delete it
            # too.
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


def _create_topic(ctx) -> dict[str, str]:
    """Create an SNS topic (registers delete_topic teardown). Returns {name,arn}."""
    name = _xname(ctx, "topic")
    sns = ctx.client("sns")
    arn = sns.create_topic(Name=name, Tags=_xsvc_tags_kv())["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=arn))
    return {"name": name, "arn": arn}


def _create_queue_subscribed(ctx, topic: dict[str, str]) -> dict[str, str]:
    """Create an SQS queue subscribed to `topic`, with a queue policy granting SNS send
    rights scoped to this topic. Registers unsubscribe + delete_queue teardown (both
    idempotent/best-effort). Returns {name,url,arn}."""
    sqs = ctx.client("sqs")
    sns = ctx.client("sns")
    name = _xname(ctx, "queue")
    url = sqs.create_queue(QueueName=name, tags=_xsvc_resource_tags())["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])[
        "Attributes"
    ]["QueueArn"]
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "sns.amazonaws.com"},
                "Action": "sqs:SendMessage",
                "Resource": arn,
                "Condition": {"ArnEquals": {"aws:SourceArn": topic["arn"]}},
            }
        ],
    }
    sqs.set_queue_attributes(QueueUrl=url, Attributes={"Policy": json.dumps(policy)})
    sub = sns.subscribe(TopicArn=topic["arn"], Protocol="sqs", Endpoint=arn)
    ctx.on_cleanup(lambda: sns.unsubscribe(SubscriptionArn=sub["SubscriptionArn"]))
    return {"name": name, "url": url, "arn": arn}


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _poll_queue_counters(ctx, sqs, queue_url, expected, cap_s=90.0):
    """Poll GetQueueAttributes until every named counter equals its expected string value.

    The ApproximateNumberOf* counters may lag up to a minute after producers stop
    (SQS GetQueueAttributes docs), so a single read is not a verdict."""
    budget_s = _budget_s(ctx, cap_s)
    start = time.monotonic()
    stop = start + min(cap_s, budget_s)
    while True:
        attrs = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=list(expected))["Attributes"]
        observed = {name: attrs.get(name) for name in expected}
        if observed == expected:
            return attrs
        if time.monotonic() >= stop:
            if budget_s < cap_s:
                raise TimeoutError(
                    f"the check's time budget ran out after {time.monotonic() - start:.1f}s, before the "
                    f"{cap_s}s counter wait ended (last observed {observed}); not graded"
                )
            raise AssertionError(f"queue counters never reached {expected}; last observed {observed}")
        time.sleep(3)


def _poll_for_message(ctx, queue_url: str, marker: str, timeout_s: float) -> bool:
    """Poll `queue_url` until a message whose body contains `marker` arrives, or `timeout_s`
    elapses; return whether it arrived. Deletes every message it reads (including any
    non-matching leftover from an earlier phase), so the queue is clean for the next phase."""
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + timeout_s
    wait_s = int(min(5.0, max(timeout_s, 1.0)))
    while time.monotonic() < deadline:
        resp = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=wait_s
        )
        found = False
        for msg in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            if marker in msg.get("Body", ""):
                found = True
        if found:
            return True
    return False


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
