"""esm-filter-criteria-non-matching-not-invoked."""

from __future__ import annotations

import json
import textwrap
import time
import zipfile
from io import BytesIO
from typing import Any

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "esm-filter-criteria-non-matching-not-invoked"

GROUP = "event-propagation"

SERVICES = ["lambda", "sqs"]


@tags(
    "axis:negative-delivery",
    "cap:c3",
    "cap:c4",
    "concern:data-plane",
    "concern:eventing",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """A record that does not match an event source mapping's FilterCriteria is deleted from the
    queue without invoking the function, while the matching record reaches the output queue."""
    in_q = _create_queue(ctx, VisibilityTimeout="60")
    out_q = _create_queue(ctx)

    handler_code = """
import boto3, os
def lambda_handler(event, context):
    sqs = boto3.client('sqs')
    for record in event.get('Records', []):
        sqs.send_message(QueueUrl=os.environ['OUT_URL'], MessageBody=record['body'])
    return {'forwarded': len(event.get('Records', []))}
"""
    fn = _create_lambda(
        ctx,
        handler_code=handler_code,
        permissions=[
            {
                "Action": [
                    "sqs:ReceiveMessage",
                    "sqs:DeleteMessage",
                    "sqs:GetQueueAttributes",
                ],
                "Resource": in_q["arn"],
            },
            {"Action": ["sqs:SendMessage"], "Resource": out_q["arn"]},
        ],
        env={"OUT_URL": out_q["url"]},
    )

    lam = ctx.client("lambda")
    # The execution role's sqs:ReceiveMessage grant propagates on IAM's own timeline; until it
    # does, CreateEventSourceMapping refuses the role with InvalidParameterValueException.
    esm = _poll_until(
        lambda: _try_create_esm(
            lam,
            EventSourceArn=in_q["arn"],
            FunctionName=fn["name"],
            BatchSize=10,
            FilterCriteria={
                "Filters": [{"Pattern": json.dumps({"body": {"kind": ["wanted"]}})}]
            },
        ),
        lambda r: r is not None,
        timeout_s=60.0,
        interval_s=3.0,
        description="CreateEventSourceMapping past IAM propagation of the execution role",
    )
    ctx.on_cleanup(
        lambda: ctx.client("lambda").delete_event_source_mapping(UUID=esm["UUID"])
    )
    _wait_esm_state(ctx, esm["UUID"], "Enabled")

    sqs = ctx.client("sqs")
    sqs.send_message(
        QueueUrl=in_q["url"],
        MessageBody=json.dumps({"kind": "unwanted", "marker": "suppressed"}),
    )
    sqs.send_message(
        QueueUrl=in_q["url"],
        MessageBody=json.dumps({"kind": "wanted", "marker": "control"}),
    )

    ctl, others = _wait_for(
        ctx,
        out_q["url"],
        lambda b: isinstance(b, dict) and b.get("marker") == "control",
        timeout_s=150.0,
    )
    assert len(ctl) >= 1, (
        "control: the matching message must be delivered to the function and forwarded to the "
        "output queue -- without it the ESM is not proven live and the negative is unprovable"
    )

    # Negative 1: the non-matching record must never have reached the function.
    others = others + _collect(ctx, out_q["url"], window_s=45.0)
    bad = [
        _body(m)
        for m in others
        if isinstance(_body(m), dict) and _body(m).get("marker") == "suppressed"
    ]
    assert bad == [], (
        f"FilterCriteria did not suppress the invocation: the function received {len(bad)} "
        f"non-matching record(s): {bad}"
    )

    # Negative 2: real Lambda still DELETES the filtered-out record from the source queue. An
    # emulator that filters by simply not reading the message leaves it stuck here.
    attrs = _queue_depth_zero(ctx, in_q["url"], timeout_s=120.0)
    assert attrs["ApproximateNumberOfMessages"] == "0", (
        f"the filtered-out record was not consumed from the source queue: {attrs}"
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


def _body(msg: dict):
    """Parse an SQS message body as JSON, falling back to the raw string."""
    raw = msg.get("Body", "")
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        return raw


def _collect(ctx, queue_url, *, window_s=30.0, max_total=10, keep=False):
    """Drain a queue over a bounded window with long-polling ReceiveMessage(MaxNumberOfMessages=10)
    and return EVERY message seen. Never raises and never swallows an assertion.

    This is the NEGATIVE observable. An empty return is only meaningful once a positive control
    has already been observed elsewhere in the check -- that is what proves enough wall-clock and
    enough propagation elapsed for a delivery to have happened if the emulator were going to make
    one. Used alone it would pass against an emulator that delivers nothing at all."""
    sqs = ctx.client("sqs")
    seen: list[dict[str, Any]] = []
    deadline = time.monotonic() + window_s
    while time.monotonic() < deadline and len(seen) < max_total:
        wait = min(5, max(1, int(deadline - time.monotonic())))
        resp = sqs.receive_message(
            QueueUrl=queue_url,
            MaxNumberOfMessages=10,
            WaitTimeSeconds=wait,
            MessageAttributeNames=["All"],
        )
        for msg in resp.get("Messages", []):
            seen.append(msg)
            if not keep:
                sqs.delete_message(
                    QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"]
                )
    return seen


def _wait_for(ctx, queue_url, predicate, *, timeout_s=60.0):
    """Poll a queue until a message whose parsed body satisfies predicate() arrives.
    Returns (matched, others) -- every non-matching message seen along the way is returned too so
    the caller can assert on leakage instead of silently discarding it."""
    matched: list[dict[str, Any]] = []
    others: list[dict[str, Any]] = []
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline and not matched:
        for msg in _collect(ctx, queue_url, window_s=min(8.0, timeout_s)):
            (matched if predicate(_body(msg)) else others).append(msg)
    return matched, others


def _queue_depth_zero(ctx, queue_url, *, timeout_s=90.0):
    """Poll until the queue reports zero visible AND zero in-flight messages.
    ApproximateNumberOfMessages is eventually consistent, hence the poll rather than one read."""
    sqs = ctx.client("sqs")

    def probe():
        return sqs.get_queue_attributes(
            QueueUrl=queue_url,
            AttributeNames=[
                "ApproximateNumberOfMessages",
                "ApproximateNumberOfMessagesNotVisible",
            ],
        )["Attributes"]

    return _poll_until(
        probe,
        lambda a: (
            a.get("ApproximateNumberOfMessages") == "0"
            and a.get("ApproximateNumberOfMessagesNotVisible") == "0"
        ),
        timeout_s=timeout_s,
        interval_s=5.0,
        description=f"{queue_url} drained to zero",
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


def _try_create_esm(lam, **kwargs):
    """CreateEventSourceMapping, or None while Lambda still refuses the fresh execution role."""
    try:
        return lam.create_event_source_mapping(**kwargs)
    except ClientError as e:
        if e.response["Error"]["Code"] == "InvalidParameterValueException":
            return None
        raise


def _wait_esm_state(ctx, uuid: str, want: str, *, timeout_s=180.0) -> None:
    """Poll an event source mapping until it reports `want`. An ESM is not wired until it reaches
    Enabled (or Disabled) -- asserting delivery/non-delivery before that is a race, and 'no
    invocation because the ESM had not started yet' is the classic false pass on this axis."""
    lam = ctx.client("lambda")
    _poll_until(
        lambda: lam.get_event_source_mapping(UUID=uuid).get("State"),
        lambda s: s == want,
        timeout_s=timeout_s,
        interval_s=5.0,
        description=f"ESM {uuid} State={want}",
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
