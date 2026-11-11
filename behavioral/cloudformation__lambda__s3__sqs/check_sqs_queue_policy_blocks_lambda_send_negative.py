"""sqs-queue-policy-blocks-lambda-send-negative."""

from __future__ import annotations

import json
import textwrap
import time
import zipfile
from io import BytesIO
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sqs-queue-policy-blocks-lambda-send-negative"

GROUP = "overly-permissive"

SERVICES = ["cloudformation", "lambda", "s3", "sqs"]


@tags("axis:rejection", "cap:c3", "cap:c7", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A queue-policy Deny on the Lambda's execution role blocks its SendMessage despite the role's
    IAM Allow, with the exact denial payload and no message delivered; the send is delivered
    before the Deny is set and again once it is removed."""
    queue = _create_queue(ctx)

    handler_code = """
import boto3, os, json
from botocore.exceptions import ClientError
def lambda_handler(event, context):
    sqs = boto3.client('sqs')
    try:
        sqs.send_message(
            QueueUrl=os.environ['QUEUE_URL'],
            MessageBody=json.dumps(event)
        )
        return {'statusCode': 200}
    except ClientError as e:
        return {'error': e.response['Error']['Code'], 'message': e.response['Error'].get('Message')}
"""
    fn = _create_lambda(
        ctx,
        handler_code=handler_code,
        permissions=[
            {"Action": ["sqs:SendMessage"], "Resource": queue["arn"]},
        ],
        env={"QUEUE_URL": queue["url"]},
    )

    # Get Lambda role ARN
    lam = ctx.client("lambda")
    sqs = ctx.client("sqs")
    fn_config = lam.get_function_configuration(FunctionName=fn["name"])
    role_arn = fn_config["Role"]

    def _drain(expect: int, timeout_s: float) -> list[str]:
        """Receive+delete up to `expect` messages, returning their bodies."""
        seen: dict[str, str] = {}
        deadline = time.monotonic() + timeout_s
        while len(seen) < expect and time.monotonic() < deadline:
            for msg in sqs.receive_message(
                QueueUrl=queue["url"], MaxNumberOfMessages=10, WaitTimeSeconds=2
            ).get("Messages", []):
                seen[msg["MessageId"]] = msg["Body"]
                sqs.delete_message(QueueUrl=queue["url"], ReceiptHandle=msg["ReceiptHandle"])
        return sorted(seen.values())

    # --- positive control: the Lambda can reach the queue before any queue policy exists -----
    baseline = _invoke_lambda(ctx, fn["name"], {"msg": "baseline"})
    baseline_payload = baseline["payload"]
    assert (
        isinstance(baseline_payload, dict)
        and baseline_payload.get("statusCode") == 200
        and "error" not in baseline_payload
    ), (
        f"baseline send (before any queue policy) must succeed: {baseline_payload!r}; "
        "the deny leg below would prove nothing"
    )
    baseline_seen = _drain(expect=1, timeout_s=_DRAIN_S)
    assert baseline_seen == [json.dumps({"msg": "baseline"})], (
        f"baseline message was not delivered to the queue: {baseline_seen!r}"
    )

    # --- break exactly one thing: a queue-policy Deny targeting the function's role -----------
    deny_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Deny",
                    "Principal": {"AWS": role_arn},
                    "Action": "sqs:SendMessage",
                    "Resource": queue["arn"],
                }
            ],
        }
    )
    sqs.set_queue_attributes(
        QueueUrl=queue["url"],
        Attributes={"Policy": deny_policy},
    )

    accepted = 0
    denied_payload = None
    deadline = time.monotonic() + _DENY_PROPAGATION_S
    while True:
        result = _invoke_lambda(ctx, fn["name"], {"msg": "blocked"})
        payload = result["payload"]
        if isinstance(payload, dict) and "error" in payload:
            denied_payload = payload
            break
        accepted += 1
        if time.monotonic() >= deadline:
            break
        time.sleep(2.0)
    assert denied_payload is not None, (
        "a queue-policy Deny targeting the Lambda role did not block sqs:SendMessage within "
        f"{_DENY_PROPAGATION_S}s ({accepted} send(s) got through): {payload!r}"
    )
    account = queue["arn"].split(":")[4]
    session = f"{role_arn.rsplit('/', 1)[1]}/{fn['name']}"
    want_denied = {
        "error": "AccessDenied",
        "message": (
            f"User: arn:aws:sts::{account}:assumed-role/{session} is not authorized to perform: "
            f"sqs:sendmessage on resource: {queue['arn']} with an explicit deny in a resource-based "
            f"policy"
        ),
    }
    assert denied_payload == want_denied, (
        f"the queue-policy Deny must refuse the send with {want_denied!r}, got {denied_payload!r}"
    )
    if accepted:
        # Sends that landed before the Deny took effect must be accounted for, not silently lost.
        _drain(expect=accepted, timeout_s=_DRAIN_S)

    resp = sqs.receive_message(
        QueueUrl=queue["url"],
        MaxNumberOfMessages=1,
        WaitTimeSeconds=2,
    )
    assert not resp.get("Messages"), "Queue should be empty after denied send"

    # --- restore: remove the Deny and the identical send succeeds again -----------------------
    sqs.set_queue_attributes(QueueUrl=queue["url"], Attributes={"Policy": ""})
    restored = _invoke_lambda(ctx, fn["name"], {"msg": "restored"})
    restored_payload = restored["payload"]
    assert (
        isinstance(restored_payload, dict)
        and restored_payload.get("statusCode") == 200
        and "error" not in restored_payload
    ), f"removing the Deny did not restore sqs:SendMessage: {restored_payload!r}"
    restored_seen = _drain(expect=1, timeout_s=_DRAIN_S)
    assert restored_seen == [json.dumps({"msg": "restored"})], (
        f"control message was not delivered after the Deny was removed: {restored_seen!r}"
    )


_XSVC_PREFIX = "sim2real-xsvc-"


def _delete_log_group_if_present(ctx, group: str) -> None:
    try:
        ctx.client("logs").delete_log_group(logGroupName=group)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise

_DRAIN_S = 20.0

_DENY_PROPAGATION_S = 30.0

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
    # IAM role trust/permission propagation before a service assumes it is handled by the
    # bounded retry in _create_function_with_retry (retries "cannot be assumed" for up to 30s),
    # not by an unconditional sleep here.
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
            # The function creates /aws/lambda/<name> on its first invoke and the group outlives the
            # function, so delete it too; Lambda creates it asynchronously, so one that never
            # appeared is not a failure.
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
