"""events-destination-config-stepfunctions-notification-format."""
from __future__ import annotations

import datetime as dt
import json
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "events-destination-config-stepfunctions-notification-format"
GROUP = "data-format"
SERVICES = ["events", "lambda", "s3", "stepfunctions"]


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:e2e", "concern:eventing", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """The event envelope delivered to a Step Functions target preserves detail,
    detail-type, and source fields exactly as published via PutEvents (Step
    Functions receives the whole EventBridge event object as execution input)."""
    sm_role_arn = _create_role(ctx, "states.amazonaws.com")
    definition = {"StartAt": "Done", "States": {"Done": {"Type": "Pass", "End": True}}}
    sm_arn = _create_state_machine(ctx, sm_role_arn, definition)

    events_role_arn = _create_role(
        ctx,
        "events.amazonaws.com",
        inline_policies={
            "start-execution": {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Action": "states:StartExecution", "Resource": sm_arn}
                ],
            }
        },
    )

    events = ctx.client("events")
    rule_name = ctx.unique_name("sim2real-rule-")
    source = "sim2real.custom"
    detail_type = "TestEvent"
    pattern = {"source": [source], "detail-type": [detail_type]}
    events.put_rule(
        Name=rule_name,
        EventPattern=json.dumps(pattern),
        State="ENABLED",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _cleanup_rule(ctx, rule_name, ["t1"]))
    events.put_targets(Rule=rule_name, Targets=[{"Id": "t1", "Arn": sm_arn, "RoleArn": events_role_arn}])

    detail = {"foo": "bar", "num": 42, "nested": {"flag": True}}
    execution = _publish_until_execution_starts(
        ctx, sm_arn, source, detail_type, detail, timeout_s=180.0
    )
    assert execution is not None, (
        f"no Step Functions execution started from the custom event within 180s "
        f"(including retries for IAM propagation of the freshly attached start-execution policy); "
        f"state machine={sm_arn}"
    )

    sfn = ctx.client("stepfunctions")
    desc = sfn.describe_execution(executionArn=execution["executionArn"])
    exec_input = json.loads(desc["input"])
    assert exec_input["source"] == source, f"expected source={source!r}, got {exec_input.get('source')!r}"
    assert exec_input["detail-type"] == detail_type, (
        f"expected detail-type={detail_type!r}, got {exec_input.get('detail-type')!r}"
    )
    assert exec_input["detail"] == detail, f"expected detail={detail!r}, got {exec_input.get('detail')!r}"


def _poll_for_new_execution(ctx, sm_arn: str, after: dt.datetime, timeout_s: float = 120.0):
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sfn.list_executions(stateMachineArn=sm_arn, maxResults=20)
        for execution in resp.get("executions", []):
            if execution["startDate"] >= after - dt.timedelta(seconds=2):
                return execution
        time.sleep(3)
    return None


def _publish_until_execution_starts(
    ctx,
    sm_arn: str,
    source: str,
    detail_type: str,
    detail: dict[str, Any],
    timeout_s: float = 180.0,
):
    """The events.amazonaws.com role's start-execution policy was just attached, and IAM's
    eventual consistency means an early PutEvents can be silently dropped by the target
    invocation before the policy propagates. Retry publishing (never a blind sleep) until an
    execution actually starts, or the deadline is spent."""
    events = ctx.client("events")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        attempt_start = dt.datetime.now(dt.timezone.utc)
        events.put_events(
            Entries=[
                {
                    "Source": source,
                    "DetailType": detail_type,
                    "Detail": json.dumps(detail),
                    "EventBusName": "default",
                }
            ]
        )
        execution = _poll_for_new_execution(ctx, sm_arn, attempt_start, timeout_s=10)
        if execution is not None:
            return execution
        time.sleep(5)
    return None


def _cleanup_rule(ctx, rule_name: str, target_ids: list[str]) -> None:
    events = ctx.client("events")
    try:
        events.remove_targets(Rule=rule_name, Ids=target_ids)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    try:
        events.delete_rule(Rule=rule_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _create_role(
    ctx,
    service_principal: str,
    inline_policies: dict[str, Any] | None = None,
) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": service_principal}, "Action": "sts:AssumeRole"}
        ],
    }
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    role_arn = resp["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    for pname, doc in (inline_policies or {}).items():
        iam.put_role_policy(RoleName=role_name, PolicyName=pname, PolicyDocument=json.dumps(doc))
    return role_arn


def _delete_role(ctx, role_name: str) -> None:
    iam = ctx.client("iam")
    try:
        for pol in iam.list_role_policies(RoleName=role_name)["PolicyNames"]:
            iam.delete_role_policy(RoleName=role_name, PolicyName=pol)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _create_state_machine(ctx, role_arn: str, definition: dict[str, Any]) -> str:
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-sm-")
    last_err = None
    resp = None
    for _ in range(10):
        try:
            resp = sfn.create_state_machine(
                name=name,
                definition=json.dumps(definition),
                roleArn=role_arn,
                type="STANDARD",
                tags=[{"key": "sim2real", "value": CHECK}],
            )
            break
        except sfn.exceptions.AccessDeniedException as e:
            last_err = e
            time.sleep(3)
    if resp is None:
        raise last_err
    arn = resp["stateMachineArn"]
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
    return arn


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
