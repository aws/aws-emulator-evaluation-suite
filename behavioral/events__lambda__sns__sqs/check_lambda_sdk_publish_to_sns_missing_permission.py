"""lambda-sdk-publish-to-sns-missing-permission."""

from __future__ import annotations

import json
import textwrap
import time
import zipfile
from io import BytesIO
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "lambda-sdk-publish-to-sns-missing-permission"

GROUP = "overly-permissive"

SERVICES = ["events", "lambda", "sns", "sqs"]


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:e2e", "concern:eventing", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Lambda whose execution role lacks sns:Publish must be denied at the SDK call boundary.

    A positive control (permission granted) and a restore leg bracket the denial, so the
    denial is distinguishable from a topic/subscription/function wiring that never worked.
    """
    topic = _create_topic(ctx)
    queue = _create_queue(ctx)
    sqs = ctx.client("sqs")
    iam = ctx.client("iam")
    lam = ctx.client("lambda")
    sns = ctx.client("sns")

    # Subscribe a queue so we can prove what was (and was not) actually delivered.
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "sns.amazonaws.com"},
                "Action": "sqs:SendMessage",
                "Resource": queue["arn"],
                "Condition": {"ArnEquals": {"aws:SourceArn": topic["arn"]}},
            }
        ],
    }
    sqs.set_queue_attributes(
        QueueUrl=queue["url"], Attributes={"Policy": json.dumps(policy)}
    )
    sub = sns.subscribe(TopicArn=topic["arn"], Protocol="sqs", Endpoint=queue["arn"])
    ctx.on_cleanup(
        lambda: ctx.client("sns").unsubscribe(SubscriptionArn=sub["SubscriptionArn"])
    )

    code = f'''
import boto3
from botocore.exceptions import ClientError
sns = boto3.client("sns")
TOPIC = "{topic["arn"]}"
def lambda_handler(event, context):
    try:
        sns.publish(TopicArn=TOPIC, Message="should-be-denied")
    except ClientError as exc:
        err = exc.response["Error"]
        return {{"error_code": err["Code"], "message": err.get("Message")}}
    return {{"error_code": None, "message": None}}
'''
    # This is the IAM identity-policy boundary for an outbound SDK call — distinct from the
    # ESM role permissions, the Lambda resource policy, and the role trust policy probed by
    # the other checks.
    role = _create_role(
        ctx, "lambda.amazonaws.com", inline_policy=_role_policy(topic["arn"])
    )
    fn = _create_function_with_retry(ctx, code, role["arn"], {})

    def invoke() -> dict[str, Any]:
        resp = lam.invoke(FunctionName=fn["name"], Payload=b"{}")
        return json.loads(resp["Payload"].read())

    # 1) Positive control: with sns:Publish granted, the call must succeed and the message
    # must actually reach the subscribed queue. This proves the topic/subscription/function
    # wiring is healthy, so a later denial can only be about the missing permission.
    granted = _poll_until(
        invoke,
        lambda r: r.get("error_code") is None,
        timeout_s=60.0,
        interval_s=3.0,
        description="sns:Publish permitted with the permission granted (positive control)",
    )
    assert granted.get("error_code") is None, (
        "positive control failed: expected sns:Publish to succeed with the permission "
        f"granted, got error_code={granted.get('error_code')!r}"
    )
    first = _drain_message(ctx, queue["url"])
    assert first["Message"] == "should-be-denied", (
        f"positive control: unexpected delivered message body {first!r}"
    )

    # 2) Break: remove sns:Publish from the execution role.
    iam.put_role_policy(
        RoleName=role["name"],
        PolicyName="inline",
        PolicyDocument=json.dumps(_role_policy(None)),
    )

    # 3) The specific denial: SNS answers AuthorizationError naming the function's assumed-role
    # session, the action and the topic.
    account = topic["arn"].split(":")[4]
    expected_denial = {
        "error_code": "AuthorizationError",
        "message": (
            f"User: arn:aws:sts::{account}:assumed-role/{role['name']}/{fn['name']} is not "
            f"authorized to perform: SNS:Publish on resource: {topic['arn']} because no "
            "identity-based policy allows the SNS:Publish action"
        ),
    }
    #
    # Removing an inline identity policy is eventually consistent: an invoke made in the
    # first few seconds after the put_role_policy call above can still succeed. That is a
    # real, expected AWS propagation window, not a leak — drain any such message (we know
    # exactly which calls produced it, since error_code was None) and keep polling for the
    # denial to take hold.
    def _invoke_draining_stray_success() -> dict[str, Any]:
        result = invoke()
        if result.get("error_code") is None:
            _drain_message(ctx, queue["url"])
        return result

    denied = _poll_until(
        _invoke_draining_stray_success,
        lambda r: r.get("error_code") is not None,
        timeout_s=60.0,
        interval_s=3.0,
        description="sns:Publish denied after removing the permission",
    )
    assert denied == expected_denial, (
        f"expected sns:Publish to be denied for a role without that permission with "
        f"{_redact(expected_denial, account)}, got {_redact(denied, account)}"
    )

    # 4) The denial is stable (not a one-off blip), and this specific call — made once
    # enforcement was already observed — left nothing behind at the destination.
    stable = invoke()
    assert stable == expected_denial, (
        f"expected the denial to be stable on a repeat call, got {_redact(stable, account)}"
    )
    leaked = sqs.receive_message(
        QueueUrl=queue["url"],
        MaxNumberOfMessages=1,
        VisibilityTimeout=1,
        WaitTimeSeconds=10,
    ).get("Messages", [])
    assert not leaked, (
        "message was published to SNS despite the role lacking sns:Publish"
    )

    # 5) Restore sns:Publish.
    iam.put_role_policy(
        RoleName=role["name"],
        PolicyName="inline",
        PolicyDocument=json.dumps(_role_policy(topic["arn"])),
    )

    # 6) The identical call now succeeds again, and delivery resumes at the destination.
    restored = _poll_until(
        invoke,
        lambda r: r.get("error_code") is None,
        timeout_s=60.0,
        interval_s=3.0,
        description="sns:Publish permitted again after restoring the permission",
    )
    assert restored.get("error_code") is None, (
        "restore failed: expected sns:Publish to succeed again once the permission was "
        f"restored, got error_code={restored.get('error_code')!r}"
    )
    last = _drain_message(ctx, queue["url"])
    assert last["Message"] == "should-be-denied", (
        f"restore: unexpected delivered message body {last!r}"
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


def _redact(value: Any, account: str) -> str:
    """``value`` as text with the account id masked, for failure messages."""
    return repr(value).replace(account, "<account>")


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
            # The function auto-creates /aws/lambda/<name> on first invoke and that log group survives
            # function deletion, so delete it too.
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


def _role_policy(publish_topic_arn: str | None) -> dict[str, Any]:
    """The execution-role inline policy: logs always allowed, sns:Publish on
    `publish_topic_arn` only when one is given (omit it to model the missing-permission
    role)."""
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
    if publish_topic_arn:
        statements.append(
            {"Effect": "Allow", "Action": ["sns:Publish"], "Resource": [publish_topic_arn]}
        )
    return {"Version": "2012-10-17", "Statement": statements}


def _drain_message(ctx, queue_url: str, timeout_s: float = 45.0) -> dict[str, Any]:
    """Poll SQS until one message arrives, delete it, and return its parsed body (raises on
    timeout)."""
    sqs = ctx.client("sqs")

    def probe() -> list[dict[str, Any]]:
        return sqs.receive_message(
            QueueUrl=queue_url,
            MaxNumberOfMessages=1,
            VisibilityTimeout=1,
            WaitTimeSeconds=10,
        ).get("Messages", [])

    messages = _poll_until(
        probe,
        lambda msgs: len(msgs) > 0,
        timeout_s=timeout_s,
        interval_s=2.0,
        description=f"message delivered to queue {queue_url}",
    )
    msg = messages[0]
    sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
    return json.loads(msg["Body"])


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


def _create_topic(ctx) -> dict[str, str]:
    """Create an SNS topic (registers delete_topic teardown). Returns {name,arn}."""
    name = _xname(ctx, "topic")
    sns = ctx.client("sns")
    arn = sns.create_topic(Name=name, Tags=_xsvc_tags_kv())["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=arn))
    return {"name": name, "arn": arn}


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
