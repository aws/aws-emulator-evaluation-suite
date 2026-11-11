"""eventbridge-rule-disabled-no-invocation-negative."""
from __future__ import annotations

import io
import json
import time
import zipfile

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "eventbridge-rule-disabled-no-invocation-negative"
GROUP = "overly-permissive"
SERVICES = ["dynamodb", "events", "lambda"]


@tags("axis:negative-delivery", "cap:c2", "cap:c3", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A DISABLED EventBridge rule does not invoke its Lambda target even when a
    matching event is published; enabling the SAME rule afterward makes a new
    matching event invoke it normally (in-file positive control)."""
    table_name = _create_ddb_table(ctx)
    role_arn = _create_lambda_role(ctx)
    function_name = ctx.unique_name("sim2real-fn-")
    function_arn = _create_lambda_function(ctx, function_name, role_arn, table_name)

    events = ctx.client("events")
    ddb = ctx.client("dynamodb")

    # A dedicated, always-ENABLED calibration rule on its OWN event pattern (a distinct
    # DetailType so it never matches what the disabled-rule test below publishes). This
    # measures real delivery latency on this account/target without ever touching the
    # enable/disable state of the rule under test — an enable-then-disable transition on
    # the SAME rule used for the negative test would leave that rule with a just-flipped
    # state, which is exactly the condition whose propagation lag this check exists to
    # rule out, so measuring latency there would contaminate the very thing being measured.
    calib_rule_name = ctx.unique_name("sim2real-calib-rule-")
    calib_pattern = {"source": ["sim2real.test"], "detail-type": ["CalibEvent"]}
    calib_rule_arn = events.put_rule(
        Name=calib_rule_name, EventPattern=json.dumps(calib_pattern), State="ENABLED"
    )["RuleArn"]
    ctx.on_cleanup(lambda: events.delete_rule(Name=calib_rule_name))
    _add_event_invoke_permission(ctx, function_name, calib_rule_arn, "sim2real-calib-stmt")
    events.put_targets(
        Rule=calib_rule_name, Targets=[{"Id": "calib-target-1", "Arn": function_arn}]
    )
    ctx.on_cleanup(
        lambda: events.remove_targets(Rule=calib_rule_name, Ids=["calib-target-1"])
    )

    marker_calib = ctx.unique_name("marker-calib-")
    t_calib = time.monotonic()
    events.put_events(
        Entries=[
            {
                "Source": "sim2real.test",
                "DetailType": "CalibEvent",
                "Detail": json.dumps({"marker": marker_calib}),
            }
        ]
    )
    _poll_until(
        lambda: ddb.get_item(
            TableName=table_name, Key={"id": {"S": marker_calib}}, ConsistentRead=True
        ).get("Item"),
        lambda i: i is not None,
        timeout_s=90.0,
        interval_s=2.0,
        description="calibration event invoked the target via the always-enabled calibration rule",
    )
    latency_s = time.monotonic() - t_calib

    # The rule under test: created DISABLED from birth and never enabled until the
    # positive control below, so there is no recent enable->disable transition whose
    # propagation lag could taint the absence measurement.
    rule_name = ctx.unique_name("sim2real-rule-")
    pattern = {"source": ["sim2real.test"], "detail-type": ["TestEvent"]}
    rule_arn = events.put_rule(
        Name=rule_name, EventPattern=json.dumps(pattern), State="DISABLED"
    )["RuleArn"]
    ctx.on_cleanup(lambda: events.delete_rule(Name=rule_name))
    created_state = events.describe_rule(Name=rule_name)["State"]
    assert created_state == "DISABLED", (
        f"expected rule {rule_name} to be created DISABLED, got {created_state!r}"
    )

    _add_event_invoke_permission(ctx, function_name, rule_arn, "sim2real-stmt")
    events.put_targets(Rule=rule_name, Targets=[{"Id": "target-1", "Arn": function_arn}])
    ctx.on_cleanup(lambda: events.remove_targets(Rule=rule_name, Ids=["target-1"]))

    # Hold for at least 3x the latency the always-enabled calibration rule was just
    # measured to need, floored at 20s so a very fast target still gets a real window
    # and capped at 90s so the check stays bounded.
    hold_s = min(max(3.0 * latency_s, 20.0), 90.0)
    interval_s = max(1.0, min(4.0, latency_s / 2.0)) if latency_s > 0 else 4.0

    marker_disabled = ctx.unique_name("marker-disabled-")
    events.put_events(
        Entries=[
            {
                "Source": "sim2real.test",
                "DetailType": "TestEvent",
                "Detail": json.dumps({"marker": marker_disabled}),
            }
        ]
    )
    _confirm_absent(
        lambda: ddb.get_item(
            TableName=table_name, Key={"id": {"S": marker_disabled}}, ConsistentRead=True
        ).get("Item"),
        hold_s=hold_s,
        interval_s=interval_s,
        description="disabled rule invoked its lambda target",
    )

    # Positive control: enabling the same rule makes a fresh matching event
    # reach the target normally.
    events.enable_rule(Name=rule_name)
    _poll_until(
        lambda: events.describe_rule(Name=rule_name)["State"],
        lambda s: s == "ENABLED",
        timeout_s=30.0,
        interval_s=2.0,
        description=f"rule {rule_name} ENABLED",
    )

    marker_enabled = ctx.unique_name("marker-enabled-")
    events.put_events(
        Entries=[
            {
                "Source": "sim2real.test",
                "DetailType": "TestEvent",
                "Detail": json.dumps({"marker": marker_enabled}),
            }
        ]
    )
    # Re-publishing after enable_rule can take a while to propagate through the
    # rule engine, so retry publishing the matching event (not just polling
    # DynamoDB) in case the very first event landed just before propagation
    # completed.
    deadline = time.monotonic() + 180.0
    next_publish = 0.0
    item = None
    while time.monotonic() < deadline:
        now = time.monotonic()
        if now >= next_publish:
            events.put_events(
                Entries=[
                    {
                        "Source": "sim2real.test",
                        "DetailType": "TestEvent",
                        "Detail": json.dumps({"marker": marker_enabled}),
                    }
                ]
            )
            next_publish = now + 20.0
        item = ddb.get_item(
            TableName=table_name, Key={"id": {"S": marker_enabled}}, ConsistentRead=True
        ).get("Item")
        if item is not None:
            break
        time.sleep(2.0)
    if item is None:
        raise AssertionError(
            f"enabled rule never invoked its target for {marker_enabled} within 180s"
        )
    stored_marker = json.loads(item["payload"]["S"])["detail"]["marker"]
    assert stored_marker == marker_enabled, (
        f"expected the re-enabled rule's target to store marker {marker_enabled!r}, "
        f"got {stored_marker!r}"
    )


_LAMBDA_CODE = '''
import json
import os
import boto3

TABLE_NAME = os.environ["TABLE_NAME"]

def handler(event, context):
    client = boto3.client("dynamodb")
    marker = None
    if isinstance(event, dict):
        marker = event.get("marker")
        if marker is None:
            detail = event.get("detail")
            if isinstance(detail, dict):
                marker = detail.get("marker")
    if marker is None:
        marker = "no-marker"
    client.put_item(
        TableName=TABLE_NAME,
        Item={
            "id": {"S": str(marker)},
            "payload": {"S": json.dumps(event)},
        },
    )
    return {"stored": str(marker)}
'''


def _poll_until(
    probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"
):
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


def _confirm_absent(probe, *, hold_s=15.0, interval_s=3.0, description="effect"):
    """Poll continuously for hold_s seconds and assert the probe stays falsy
    throughout the whole window (not a single check at the end)."""
    deadline = time.monotonic() + hold_s
    while time.monotonic() < deadline:
        result = probe()
        if result:
            raise AssertionError(f"{description} unexpectedly became present: {result!r}")
        time.sleep(interval_s)


def _make_lambda_zip(code: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", code)
    return buf.getvalue()


def _create_lambda_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-lambda-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust)
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    basic_policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=basic_policy_arn)
    ctx.on_cleanup(
        lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=basic_policy_arn)
    )
    inline_policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "dynamodb:PutItem", "Resource": "*"}],
    }
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="sim2real-ddb-write",
        PolicyDocument=json.dumps(inline_policy),
    )
    ctx.on_cleanup(
        lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="sim2real-ddb-write")
    )
    return role_arn


def _create_lambda_function(ctx, function_name: str, role_arn: str, table_name: str) -> str:
    lam = ctx.client("lambda")
    zip_bytes = _make_lambda_zip(_LAMBDA_CODE)
    last_err = None
    deadline = time.monotonic() + 90.0
    resp = None
    while time.monotonic() < deadline:
        try:
            ctx.on_cleanup(lambda _n=function_name: _delete_lambda_log_group(ctx, _n))
            resp = lam.create_function(
                FunctionName=function_name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="index.handler",
                Code={"ZipFile": zip_bytes},
                Timeout=30,
                Environment={"Variables": {"TABLE_NAME": table_name}},
            )
            break
        except lam.exceptions.InvalidParameterValueException as exc:
            last_err = exc
            time.sleep(3.0)
    if resp is None:
        raise AssertionError(f"lambda create_function never succeeded: {last_err}")
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=function_name))
    _poll_until(
        lambda: lam.get_function(FunctionName=function_name)["Configuration"]["State"],
        lambda s: s == "Active",
        timeout_s=60,
        interval_s=2.0,
        description=f"function {function_name} Active",
    )
    return resp["FunctionArn"]


def _create_ddb_table(ctx) -> str:
    ddb = ctx.client("dynamodb")
    table_name = ctx.unique_name("sim2real-tbl-")
    ddb.create_table(
        TableName=table_name,
        AttributeDefinitions=[{"AttributeName": "id", "AttributeType": "S"}],
        KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}],
        BillingMode="PAY_PER_REQUEST",
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table_name))
    _poll_until(
        lambda: ddb.describe_table(TableName=table_name)["Table"]["TableStatus"],
        lambda s: s == "ACTIVE",
        timeout_s=60,
        interval_s=2.0,
        description=f"table {table_name} ACTIVE",
    )
    return table_name


def _add_event_invoke_permission(ctx, function_name: str, rule_arn: str, statement_id: str) -> None:
    lam = ctx.client("lambda")
    lam.add_permission(
        FunctionName=function_name,
        StatementId=statement_id,
        Action="lambda:InvokeFunction",
        Principal="events.amazonaws.com",
        SourceArn=rule_arn,
    )
    ctx.on_cleanup(
        lambda: lam.remove_permission(FunctionName=function_name, StatementId=statement_id)
    )


def _delete_lambda_log_group(ctx, function_name: str) -> None:
    """Delete the log group Lambda creates on a function's first log line; one never created is fine."""
    try:
        ctx.client("logs").delete_log_group(logGroupName=f"/aws/lambda/{function_name}")
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
