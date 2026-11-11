"""scheduler-lambda-target-input-payload-fidelity."""

from __future__ import annotations

import json
import textwrap
import time
import zipfile
from datetime import datetime, timedelta, timezone
from io import BytesIO
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "scheduler-lambda-target-input-payload-fidelity"

GROUP = "event-propagation"

SERVICES = ["dynamodb", "lambda", "scheduler"]


# timing:real-time — schedule: 30 s https://docs.aws.amazon.com/scheduler/latest/UserGuide/schedule-types.html
@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "concern:eventing", "concern:representation", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """EventBridge Scheduler delivers its Target Input to a Lambda target verbatim and substitutes
    the <aws.scheduler.*> context attributes, so no literal placeholder reaches the payload.
    """
    ddb = ctx.client("dynamodb")
    scheduler = ctx.client("scheduler")
    sink = _create_table(ctx)

    code = """
    import json, os
    import boto3
    ddb = boto3.client("dynamodb")
    SINK = os.environ["SINK_TABLE"]

    def handler(event, context):
        ddb.put_item(TableName=SINK, Item={
            "pk": {"S": event.get("marker", "MISSING")},
            "event": {"S": json.dumps(event)},
        })
        return {"ok": True}
    """
    fn = _create_lambda(
        ctx,
        code,
        permissions=[{"Action": ["dynamodb:PutItem"], "Resource": sink["arn"]}],
        env={"SINK_TABLE": sink["name"]},
    )

    sched_role = _create_role(
        ctx,
        "scheduler.amazonaws.com",
        inline_policy={
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "lambda:InvokeFunction",
                    "Resource": [fn["arn"], fn["arn"] + ":*"],
                }
            ],
        },
    )

    marker = _xname(ctx, "smark")
    nested = {"a": [1, 2, 3], "b": {"c": "d"}, "unicode": "caf\u00e9"}
    payload = {
        "marker": marker,
        "nested": nested,
        "scheduled_time": "<aws.scheduler.scheduled-time>",
        "attempt": "<aws.scheduler.attempt-number>",
        "schedule_arn": "<aws.scheduler.schedule-arn>",
        "execution_id": "<aws.scheduler.execution-id>",
    }
    # 30s out: at() has one-second granularity but Scheduler needs the fire time in the future,
    # and the role must have propagated before it is assumed.
    schedule = _create_one_time_schedule(
        ctx,
        target_arn=fn["arn"],
        role_arn=sched_role["arn"],
        input_payload=payload,
        at_offset_s=30,
    )
    described = scheduler.get_schedule(Name=schedule["name"])
    assert described["ScheduleExpression"] == schedule["expression"], (
        f"schedule expression not stored: {described.get('ScheduleExpression')!r}"
    )
    assert described["Target"]["Arn"] == fn["arn"], (
        f"target ARN not stored: {described['Target']!r}"
    )
    schedule_arn = described["Arn"]

    # 360s: 30s until the fire time + Scheduler's own delivery lag + Lambda cold start, all
    # serialized. There is no earlier observable, so the deadline has to cover the whole wait.
    item = _wait_for_effect(
        lambda: ddb.get_item(TableName=sink["name"], Key={"pk": {"S": marker}}).get("Item"),
        lambda i: i is not None,
        timeout_s=360,
        interval_s=10.0,
        description=f"scheduled Lambda invocation delivering {marker}",
    )
    delivered = json.loads(item["event"]["S"])

    # Verbatim halves: the Input is the WHOLE event, with no Scheduler envelope wrapped around it.
    assert set(delivered) == set(payload), (
        f"Scheduler must deliver the Input as the entire Lambda event, no envelope added or "
        f"fields dropped.\nexpected keys {sorted(payload)}\ngot keys      {sorted(delivered)}"
    )
    assert delivered["marker"] == marker, f"marker mangled: {delivered['marker']!r}"
    assert delivered["nested"] == nested, (
        f"nested Input structure not preserved through the JSON Input string: "
        f"{delivered['nested']!r} != {nested!r}"
    )

    # Substitution halves: no literal placeholder survives, and each value is the real thing.
    raw = json.dumps(delivered)
    assert "<aws.scheduler." not in raw, (
        f"Scheduler context attributes were not substituted; the literal placeholders reached "
        f"the target: {raw}"
    )
    expected_time = schedule["fire_at"].strftime("%Y-%m-%dT%H:%M:%SZ")
    assert delivered["scheduled_time"] == expected_time, (
        f"<aws.scheduler.scheduled-time> must be the schedule's UTC fire time "
        f"{expected_time!r}, got {delivered['scheduled_time']!r}"
    )
    assert delivered["attempt"] == "1", (
        f"<aws.scheduler.attempt-number> must be 1 for a first, successful delivery, got "
        f"{delivered['attempt']!r}"
    )
    assert delivered["schedule_arn"] == schedule_arn, (
        f"<aws.scheduler.schedule-arn> must be this schedule's own ARN "
        f"(region {ctx.region!r}, account {ctx.account!r}): expected {schedule_arn!r}, got "
        f"{delivered['schedule_arn']!r}"
    )
    assert len(delivered["execution_id"]) >= 8, (
        f"<aws.scheduler.execution-id> must be a real execution identifier, got "
        f"{delivered['execution_id']!r}"
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


def _wait_for_effect(
    probe, predicate, timeout_s=120.0, interval_s=2.0, description="effect"
):
    """Poll for an async cross-service effect; 120s covers cold start + first delivery."""
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
    """Create an IAM role and register its teardown. Returns {name,arn}."""
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
    # No sleep: both callers retry the IAM-propagation refusal with their own bounded deadline.
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


def _reap_log_group(
    logs, name: str, *, reads: int = 3, interval_s: float = 5.0, budget_s: float = 180.0
) -> None:
    """Delete log group `name` until `reads` consecutive reads find it absent.

    A buffered log flush can recreate the group right after a delete, so this re-deletes
    rather than deleting once; raises if it is still coming back when `budget_s` runs out.
    """
    deadline = time.monotonic() + budget_s
    absent = 0
    while True:
        groups = logs.describe_log_groups(logGroupNamePrefix=name).get("logGroups", [])
        if any(g["logGroupName"] == name for g in groups):
            absent = 0
            try:
                logs.delete_log_group(logGroupName=name)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise
        else:
            absent += 1
            if absent >= reads:
                return
        if time.monotonic() > deadline:
            raise AssertionError(
                f"log group {name} still present after {budget_s}s of deletes; "
                f"{absent} consecutive clean read(s)"
            )
        time.sleep(interval_s)


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
    """Create a Lambda, retrying through IAM role propagation, then wait until Active.
    Registers the function's teardown, which LIFO runs before its role's."""
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
            # function deletion, and a buffered flush can recreate it after a first delete, so this
            # reaps in a loop rather than deleting once.
            ctx.on_cleanup(
                lambda: _reap_log_group(ctx.client("logs"), f"/aws/lambda/{name}")
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
    """Create a Lambda whose execution role allows only `permissions` (plus logs).
    Role and function each register their own teardown. Returns {name,arn}."""
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


def _create_table(
    ctx,
    key_schema=None,
    attributes=None,
    stream=False,
    stream_view_type="NEW_AND_OLD_IMAGES",
) -> dict[str, str]:
    """Create a DynamoDB table (PAY_PER_REQUEST; waits table_exists; registers delete_table).
    Returns {name,arn[,stream_arn]}."""
    name = _xname(ctx, "tbl")
    ddb = ctx.client("dynamodb")
    params: dict[str, Any] = {
        "TableName": name,
        "KeySchema": key_schema or [{"AttributeName": "pk", "KeyType": "HASH"}],
        "AttributeDefinitions": attributes
        or [{"AttributeName": "pk", "AttributeType": "S"}],
        "BillingMode": "PAY_PER_REQUEST",
        "Tags": _xsvc_tags_kv(),
    }
    if stream:
        params["StreamSpecification"] = {
            "StreamEnabled": True,
            "StreamViewType": stream_view_type,
        }
    resp = ddb.create_table(**params)
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=name))
    ddb.get_waiter("table_exists").wait(
        TableName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 30}
    )
    result = {"name": name, "arn": resp["TableDescription"]["TableArn"]}
    if stream:
        result["stream_arn"] = resp["TableDescription"].get("LatestStreamArn", "")
    return result


def _create_one_time_schedule(
    ctx, *, target_arn, role_arn, input_payload, at_offset_s=90, **extra
) -> dict[str, Any]:
    """Create a one-time at() schedule (registers delete_schedule).

    FlexibleTimeWindow OFF + explicit UTC make the fire time exact; retries cover IAM propagation.
    """
    scheduler = ctx.client("scheduler")
    name = _xname(ctx, "sched")
    last_err = None
    for _ in range(8):
        # Each attempt keeps the fire time at_offset_s in the future, whatever the retries took.
        fire_at = datetime.now(timezone.utc) + timedelta(seconds=at_offset_s)
        # at() takes a naive local-to-the-given-timezone timestamp with second granularity.
        expression = "at(" + fire_at.strftime("%Y-%m-%dT%H:%M:%S") + ")"
        try:
            scheduler.create_schedule(
                Name=name,
                ScheduleExpression=expression,
                ScheduleExpressionTimezone="UTC",
                FlexibleTimeWindow={"Mode": "OFF"},
                Target={
                    "Arn": target_arn,
                    "RoleArn": role_arn,
                    "Input": json.dumps(input_payload),
                },
                **extra,
            )
            break
        except ClientError as exc:
            msg = str(exc)
            if "assume" in msg or "ValidationException" in msg:
                last_err = exc
                time.sleep(5)
                continue
            raise
    else:
        raise AssertionError(f"could not create schedule {name}: {last_err}")
    ctx.on_cleanup(lambda: ctx.client("scheduler").delete_schedule(Name=name))
    return {"name": name, "expression": expression, "fire_at": fire_at}


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
