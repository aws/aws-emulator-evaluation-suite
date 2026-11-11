"""s3-write-triggers-eventbridge-rule-to-stepfunctions."""
from __future__ import annotations

import datetime as dt
import json
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "s3-write-triggers-eventbridge-rule-to-stepfunctions"
GROUP = "event-chain"
SERVICES = ["events", "lambda", "s3", "stepfunctions"]


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """An S3 PutObject event, routed through EventBridge (bucket-level notifications
    enabled), starts a Step Functions execution whose input carries the original
    S3 event detail -- closing the S3 -> EventBridge -> Step Functions loop."""
    bucket = _create_bucket(ctx)

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

    s3 = ctx.client("s3")
    s3.put_bucket_notification_configuration(
        Bucket=bucket, NotificationConfiguration={"EventBridgeConfiguration": {}}
    )

    events = ctx.client("events")
    rule_name = ctx.unique_name("sim2real-rule-")
    pattern = {
        "source": ["aws.s3"],
        "detail-type": ["Object Created"],
        "detail": {"bucket": {"name": [bucket]}},
    }
    rule_arn = events.put_rule(Name=rule_name, EventPattern=json.dumps(pattern), State="ENABLED")["RuleArn"]
    events.tag_resource(ResourceARN=rule_arn, Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: _cleanup_rule(ctx, rule_name, ["t1"]))
    events.put_targets(Rule=rule_name, Targets=[{"Id": "t1", "Arn": sm_arn, "RoleArn": events_role_arn}])

    # A freshly attached IAM trust/permission policy is not immediately visible to EventBridge:
    # a target invocation attempted before it propagates gets AccessDenied, which EventBridge
    # does not retry, so the event is dropped rather than merely delayed. A single write plus a
    # long poll for its effect (a dropped delivery is never retried, so no delayed execution appears) cannot
    # tell that apart from "no delivery path at all" -- so retry the write itself, bounded, until
    # an execution shows up or the deadline passes.
    execution = None
    object_key = None
    trigger_deadline = time.monotonic() + 150
    while execution is None and time.monotonic() < trigger_deadline:
        start_time = dt.datetime.now(dt.timezone.utc)
        object_key = ctx.unique_name("sim2real-trigger-") + ".txt"
        s3.put_object(Bucket=bucket, Key=object_key, Body=b"hello-eventbridge")
        execution = _poll_for_new_execution(ctx, sm_arn, start_time, timeout_s=20)
    assert execution is not None, "no Step Functions execution was started from the S3 event"

    sfn = ctx.client("stepfunctions")
    desc = _poll_for_terminal_status(ctx, execution["executionArn"], timeout_s=60)
    assert desc["status"] == "SUCCEEDED", f"execution did not succeed: {desc['status']} {desc.get('error', '')}"
    exec_input = json.loads(desc["input"])
    assert exec_input["detail-type"] == "Object Created", f"expected Object Created, got {exec_input.get('detail-type')}"
    assert exec_input["source"] == "aws.s3", f"expected aws.s3, got {exec_input.get('source')}"
    assert exec_input["detail"]["bucket"]["name"] == bucket, (
        f"expected bucket {bucket}, got {exec_input['detail']['bucket'].get('name')}"
    )
    assert exec_input["detail"]["object"]["key"] == object_key, (
        f"expected object key {object_key}, got {exec_input['detail']['object'].get('key')}"
    )


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


_TERMINAL_STATUSES = frozenset({"SUCCEEDED", "FAILED", "TIMED_OUT", "ABORTED"})


def _poll_for_terminal_status(ctx, execution_arn: str, timeout_s: float = 60.0) -> dict[str, Any]:
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + timeout_s
    desc = sfn.describe_execution(executionArn=execution_arn)
    while desc["status"] not in _TERMINAL_STATUSES:
        if time.monotonic() >= deadline:
            raise AssertionError(f"execution stuck in {desc['status']} past {timeout_s}s")
        time.sleep(2)
        desc = sfn.describe_execution(executionArn=execution_arn)
    return desc


def _cleanup_rule(ctx, rule_name: str, target_ids: list[str]) -> None:
    events = ctx.client("events")
    try:
        events.remove_targets(Rule=rule_name, Ids=target_ids)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    try:
        events.delete_rule(Name=rule_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-bkt-").lower().replace("_", "-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=name)
    else:
        s3.create_bucket(Bucket=name, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, name))
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
    return name


def _empty_and_delete_bucket(ctx, name: str) -> None:
    s3 = ctx.client("s3")
    try:
        resp = s3.list_objects_v2(Bucket=name)
        for obj in resp.get("Contents", []):
            s3.delete_object(Bucket=name, Key=obj["Key"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise
    try:
        s3.delete_bucket(Bucket=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
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
            last_err = e  # role trust policy not yet propagated to the SFN service
            time.sleep(3)
    if resp is None:
        raise last_err
    arn = resp["stateMachineArn"]
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
    return arn


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
