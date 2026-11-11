"""eventbridge-fanout-lambda-sqs-sfn."""

from __future__ import annotations

import json
import textwrap
import time
import zipfile
from io import BytesIO
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "eventbridge-fanout-lambda-sqs-sfn"

GROUP = "event-propagation"

SERVICES = ["events", "lambda", "stepfunctions", "sqs"]

_FORWARD_EVENT_CODE = """
import json, boto3, os

sqs = boto3.client("sqs")


def lambda_handler(event, context):
    sqs.send_message(
        QueueUrl=os.environ["SINK_QUEUE_URL"],
        MessageBody=json.dumps(event),
    )
    return {"ok": True}
"""

_PASS_DEFINITION = {
    "StartAt": "Done",
    "States": {"Done": {"Type": "Pass", "End": True}},
}


def _put_rule(ctx, pattern, name_hint="rule"):
    events = ctx.client("events")
    rule_name = ctx.unique_name(name_hint)
    resp = events.put_rule(
        Name=rule_name, EventPattern=json.dumps(pattern), State="ENABLED"
    )
    ctx.on_cleanup(lambda: ctx.client("events").delete_rule(Name=rule_name))
    return rule_name, resp["RuleArn"]


def _allow_events_to_send(ctx, queue, rule_arn=None):
    """Attach a queue policy allowing events.amazonaws.com to sqs:SendMessage."""
    stmt = {
        "Sid": "AllowEventBridgeSend",
        "Effect": "Allow",
        "Principal": {"Service": "events.amazonaws.com"},
        "Action": "sqs:SendMessage",
        "Resource": queue["arn"],
    }
    if rule_arn:
        stmt["Condition"] = {"ArnEquals": {"aws:SourceArn": rule_arn}}
    ctx.client("sqs").set_queue_attributes(
        QueueUrl=queue["url"],
        Attributes={
            "Policy": json.dumps({"Version": "2012-10-17", "Statement": [stmt]})
        },
    )


def _drain(ctx, queue_url, rounds=8):
    """Collect messages arriving during a settle window using SQS long polling."""
    sqs = ctx.client("sqs")
    collected = []
    for _ in range(rounds):
        resp = sqs.receive_message(
            QueueUrl=queue_url,
            MaxNumberOfMessages=10,
            WaitTimeSeconds=5,
            MessageAttributeNames=["All"],
        )
        collected.extend(resp.get("Messages", []))
    return collected


def _put_events_until(ctx, entries, probe, timeout_s=75, interval_s=6):
    """PutEvents repeatedly until a downstream effect appears.

    Rule/target creation on the default bus is eventually consistent: an event
    published immediately after PutTargets can be silently dropped. Republishing
    while polling makes the positive path deterministic.
    """
    events = ctx.client("events")

    def attempt():
        resp = events.put_events(Entries=entries)
        assert resp["FailedEntryCount"] == 0, resp
        return probe()

    return _poll_until(
        attempt, lambda r: bool(r), timeout_s=timeout_s, interval_s=interval_s
    )


def _receive_raw(ctx, queue_url, max_messages=10):
    resp = ctx.client("sqs").receive_message(
        QueueUrl=queue_url,
        MaxNumberOfMessages=max_messages,
        WaitTimeSeconds=5,
        MessageAttributeNames=["All"],
    )
    return resp.get("Messages", [])


def _await_envelope(ctx, queue_url, event_id, timeout_s=60):
    """Poll a queue until an EventBridge envelope with the given event id arrives."""
    found = {}

    def probe():
        for msg in _receive_raw(ctx, queue_url):
            try:
                body = json.loads(msg["Body"])
            except (json.JSONDecodeError, ValueError):
                continue
            if body.get("id") == event_id:
                found["body"] = body
                return True
        return False

    _poll_until(probe, lambda r: r, timeout_s=timeout_s, interval_s=4)
    return found["body"]


@tags(
    "axis:happy-path",
    "cap:c3",
    "concern:data-plane",
    "concern:e2e",
    "concern:eventing",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """One event fans out to Lambda, SQS and Step Functions with an identical envelope."""
    direct_q = _create_queue(ctx)
    sink_q = _create_queue(ctx)

    fn = _create_lambda(
        ctx,
        handler_code=_FORWARD_EVENT_CODE,
        permissions=[{"Action": ["sqs:SendMessage"], "Resource": sink_q["arn"]}],
        env={"SINK_QUEUE_URL": sink_q["url"]},
    )
    sfn_role = _create_role_stmts(ctx, "states.amazonaws.com", [], "sfn-role-fanout")
    sm_arn = _create_state_machine_role(ctx, _PASS_DEFINITION, sfn_role, "sm-fanout")
    eb_role = _create_role_stmts(
        ctx,
        "events.amazonaws.com",
        [{"Effect": "Allow", "Action": "states:StartExecution", "Resource": sm_arn}],
        "eb-role-fanout",
    )

    rule_name, rule_arn = _put_rule(
        ctx, {"source": ["sim2real.xsvc.fanout"]}, "rule-fanout"
    )
    _allow_events_to_send(ctx, direct_q, rule_arn)
    ctx.client("lambda").add_permission(
        FunctionName=fn["name"],
        StatementId="eb-fanout",
        Action="lambda:InvokeFunction",
        Principal="events.amazonaws.com",
        SourceArn=rule_arn,
    )

    events = ctx.client("events")

    def _try_put_targets():
        # eb_role's trust policy may not have propagated yet; retry on the
        # specific IAM-propagation error rather than sleeping blind.
        try:
            return events.put_targets(
                Rule=rule_name,
                Targets=[
                    {"Id": "t-lambda", "Arn": fn["arn"]},
                    {"Id": "t-sqs", "Arn": direct_q["arn"]},
                    {"Id": "t-sfn", "Arn": sm_arn, "RoleArn": eb_role},
                ],
            )
        except ClientError as e:
            if "cannot be assumed" in str(e) or "not authorized" in str(e).lower():
                return None
            raise

    resp = _poll_until(
        _try_put_targets,
        lambda r: r is not None,
        timeout_s=30,
        interval_s=3,
        description="PutTargets accepting the EventBridge->SFN role (IAM trust propagation)",
    )
    ctx.on_cleanup(
        lambda: ctx.client("events").remove_targets(
            Rule=rule_name, Ids=["t-lambda", "t-sqs", "t-sfn"]
        )
    )
    assert resp["FailedEntryCount"] == 0, resp

    # Warm up until the rule and its targets are live (eventual consistency),
    # then clear the warm-up copies so the correlated event stands alone.
    _put_events_until(
        ctx,
        [
            {
                "Source": "sim2real.xsvc.fanout",
                "DetailType": "Fan",
                "Detail": json.dumps({"id": "warmup"}),
            }
        ],
        lambda: _receive_raw(ctx, direct_q["url"]),
        timeout_s=60,
    )
    _drain(ctx, direct_q["url"], rounds=2)
    _drain(ctx, sink_q["url"], rounds=2)

    # Publish exactly one correlated event and track it by its EventId.
    final = events.put_events(
        Entries=[
            {
                "Source": "sim2real.xsvc.fanout",
                "DetailType": "Fan",
                "Detail": json.dumps({"id": "f-1"}),
            }
        ]
    )
    assert final["FailedEntryCount"] == 0, final
    event_id = final["Entries"][0]["EventId"]

    sqs_env = _await_envelope(ctx, direct_q["url"], event_id, timeout_s=60)
    lam_env = _await_envelope(ctx, sink_q["url"], event_id, timeout_s=60)

    sfn = ctx.client("stepfunctions")
    execs = _poll_until(
        lambda: [
            e
            for e in sfn.list_executions(stateMachineArn=sm_arn)["executions"]
            if json.loads(
                sfn.describe_execution(executionArn=e["executionArn"])["input"]
            ).get("id")
            == event_id
        ],
        lambda e: len(e) > 0,
        timeout_s=60,
        interval_s=5,
    )

    assert sqs_env["detail"]["id"] == "f-1", sqs_env
    assert lam_env["detail"]["id"] == "f-1", lam_env
    assert sqs_env["id"] == lam_env["id"] == event_id, (
        "fan-out delivered different event ids to the SQS and Lambda targets"
    )

    sfn_input = json.loads(
        sfn.describe_execution(executionArn=execs[0]["executionArn"])["input"]
    )
    assert sfn_input["detail"]["id"] == "f-1", sfn_input
    assert sfn_input["id"] == sqs_env["id"], (
        "fan-out event id differs for the Step Functions target"
    )


_XSVC_PREFIX = "sim2real-xsvc-"

_MANAGED_TAG_KEY = "sim2real:managed"


def _create_role_stmts(ctx, service_principal, statements, name_hint="role"):
    """Create a role trusting *service_principal* with an optional inline policy."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name(name_hint)
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": service_principal},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust)
    )
    ctx.on_cleanup(lambda: ctx.client("iam").delete_role(RoleName=role_name))
    if statements:
        iam.put_role_policy(
            RoleName=role_name,
            PolicyName="inline",
            PolicyDocument=json.dumps(
                {"Version": "2012-10-17", "Statement": statements}
            ),
        )
        ctx.on_cleanup(
            lambda: ctx.client("iam").delete_role_policy(
                RoleName=role_name, PolicyName="inline"
            )
        )
    # Service-principal trust propagation has no pollable signal of its own;
    # every caller of this role retries the operation that actually needs it
    # (create_state_machine, put_targets) on the specific propagation error.
    return role["Role"]["Arn"]


def _create_state_machine_role(ctx, definition, role_arn, name_hint="sm"):
    """Create a state machine, tolerating IAM propagation delay."""
    sfn = ctx.client("stepfunctions")
    sm_name = ctx.unique_name(name_hint)

    def probe():
        try:
            return sfn.create_state_machine(
                name=sm_name, definition=json.dumps(definition), roleArn=role_arn
            )
        except ClientError:
            return None

    sm = _wait_for_effect(probe, lambda r: r is not None, timeout_s=90)
    ctx.on_cleanup(
        lambda: ctx.client("stepfunctions").delete_state_machine(
            stateMachineArn=sm["stateMachineArn"]
        )
    )
    return sm["stateMachineArn"]


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
    # No blind sleep here: _create_function_with_retry already retries
    # create_function on the specific IAM role-propagation error below.
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
            # function deletion, so it would be left behind. Delete it
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
