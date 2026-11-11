"""eventbridge-rule-no-permission-to-invoke-lambda."""

from __future__ import annotations

import json
import textwrap
import time
import zipfile
from io import BytesIO
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "eventbridge-rule-no-permission-to-invoke-lambda"

GROUP = "overly-permissive"

SERVICES = ["events", "iam", "lambda", "sqs"]


def _sqs_forwarder_code(queue_url_env: str) -> str:
    return (
        "import boto3, json, os\n"
        "def lambda_handler(event, context):\n"
        "    kwargs = {}\n"
        "    if os.environ.get('AWS_ENDPOINT_URL'):\n"
        "        kwargs['endpoint_url'] = os.environ['AWS_ENDPOINT_URL']\n"
        "    sqs = boto3.client('sqs', **kwargs)\n"
        f"    sqs.send_message(QueueUrl=os.environ['{queue_url_env}'], MessageBody='invoked')\n"
        "    return {}\n"
    )


@tags(
    "axis:negative-delivery",
    "cap:c3",
    "concern:data-plane",
    "concern:eventing",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """A rule target Lambda without invoke permission never receives the event (its queue stays
    empty), while a permitted control target on the same rule, fired by the same event,
    delivers."""
    queue_deny = _create_queue(ctx)
    queue_ok = _create_queue(ctx)
    fn_deny = _create_lambda(
        ctx,
        handler_code=_sqs_forwarder_code("QUEUE_URL"),
        permissions=[{"Action": ["sqs:SendMessage"], "Resource": queue_deny["arn"]}],
        env={"QUEUE_URL": queue_deny["url"]},
    )
    fn_ok = _create_lambda(
        ctx,
        handler_code=_sqs_forwarder_code("QUEUE_URL"),
        permissions=[{"Action": ["sqs:SendMessage"], "Resource": queue_ok["arn"]}],
        env={"QUEUE_URL": queue_ok["url"]},
    )

    events = ctx.client("events")
    bus_name = ctx.unique_name("bus-")
    events.create_event_bus(Name=bus_name)
    ctx.on_cleanup(lambda: ctx.client("events").delete_event_bus(Name=bus_name))

    rule_name = ctx.unique_name("rule-")
    events.put_rule(
        Name=rule_name,
        EventBusName=bus_name,
        EventPattern=json.dumps({"source": ["sim2real.noperm"]}),
        State="ENABLED",
    )
    ctx.on_cleanup(
        lambda: ctx.client("events").delete_rule(Name=rule_name, EventBusName=bus_name)
    )
    ctx.on_cleanup(
        lambda: ctx.client("events").remove_targets(
            Rule=rule_name, EventBusName=bus_name, Ids=["deny", "ok"]
        )
    )

    lam = ctx.client("lambda")
    rule_arn = (
        f"arn:aws:events:{ctx.region}:{fn_ok['arn'].split(':')[4]}:"
        f"rule/{bus_name}/{rule_name}"
    )
    lam.add_permission(
        FunctionName=fn_ok["name"],
        StatementId="eb-invoke",
        Action="lambda:InvokeFunction",
        Principal="events.amazonaws.com",
        SourceArn=rule_arn,
    )
    # Deliberately NOT granting fn_deny an invoke permission — that is the subject under test.

    events.put_targets(
        Rule=rule_name,
        EventBusName=bus_name,
        Targets=[
            {"Id": "deny", "Arn": fn_deny["arn"]},
            {"Id": "ok", "Arn": fn_ok["arn"]},
        ],
    )

    events.put_events(
        Entries=[
            {
                "Source": "sim2real.noperm",
                "DetailType": "Test",
                "Detail": json.dumps({"x": 1}),
                "EventBusName": bus_name,
            }
        ]
    )

    sqs = ctx.client("sqs")

    def _probe_ok():
        resp = sqs.receive_message(
            QueueUrl=queue_ok["url"], MaxNumberOfMessages=1, WaitTimeSeconds=5
        )
        return resp.get("Messages", [])

    ok_msgs = _poll_until(
        _probe_ok,
        lambda m: len(m) > 0,
        timeout_s=60.0,
        interval_s=2.0,
        description="permitted twin target delivered to its own queue",
    )
    assert ok_msgs, (
        "Twin control with invoke permission never delivered — the rule/target wiring "
        "itself is broken, so the withheld queue proves nothing"
    )

    # Freeze detector: now that the twin control has proved the same-instant dispatch actually
    # delivers, the denied leg must return empty on every one of several independent reads spanning
    # comparable wall-clock time — never a single bare sleep.
    for _ in range(3):
        resp = sqs.receive_message(
            QueueUrl=queue_deny["url"], MaxNumberOfMessages=1, WaitTimeSeconds=5
        )
        assert not resp.get("Messages", []), (
            "Lambda was invoked without permission — emulator is too permissive"
        )
        time.sleep(2)
    attrs = sqs.get_queue_attributes(
        QueueUrl=queue_deny["url"], AttributeNames=["ApproximateNumberOfMessages"]
    )
    depth = attrs["Attributes"]["ApproximateNumberOfMessages"]
    assert depth == "0", f"Denied target's queue should have depth 0, got {depth}"


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
    # IAM propagation is absorbed by the bounded retry at first use
    # (_create_function_with_retry), the same on every target.
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
