"""s3-write-eventbridge-rule-missing-startexecution-permission."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "s3-write-eventbridge-rule-missing-startexecution-permission"
GROUP = "permission-boundary"
SERVICES = ["events", "lambda", "s3", "stepfunctions"]


@tags("axis:negative-delivery", "cap:c3", "cap:c7", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """Of two targets on one rule pointing at the same state machine, only the one whose role
    has states:StartExecution starts an execution: one S3 event adds exactly one execution."""
    bucket = _create_bucket(ctx)

    sm_role_arn = _create_role(ctx, "states.amazonaws.com")
    definition = {"StartAt": "Done", "States": {"Done": {"Type": "Pass", "End": True}}}
    sm_arn = _create_state_machine(ctx, sm_role_arn, definition)

    good_role_arn = _create_role(
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
    bad_role_arn = _create_role(
        ctx,
        "events.amazonaws.com",
        inline_policies={
            "describe-only": {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Action": "states:DescribeStateMachine", "Resource": sm_arn}
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
    events.put_rule(Name=rule_name, EventPattern=json.dumps(pattern), State="ENABLED")
    ctx.on_cleanup(lambda: _cleanup_rule(ctx, rule_name, ["t-bad", "t-good"]))
    events.put_targets(
        Rule=rule_name,
        Targets=[
            {"Id": "t-bad", "Arn": sm_arn, "RoleArn": bad_role_arn},
            {"Id": "t-good", "Arn": sm_arn, "RoleArn": good_role_arn},
        ],
    )

    sfn = ctx.client("stepfunctions")
    before_count = len(sfn.list_executions(stateMachineArn=sm_arn, maxResults=100)["executions"])

    # EventBridge does not retry an AccessDeniedException from a just-created target role
    # that hasn't finished propagating — it drops that delivery attempt for good. So a
    # single fire right after attaching the policies would be flaky: re-fire fresh S3
    # events (new object keys) until the permitted target's role has propagated and an
    # execution actually appears.
    after_count = before_count
    fire_deadline = time.monotonic() + 120
    while time.monotonic() < fire_deadline and after_count == before_count:
        object_key = ctx.unique_name("sim2real-trigger-") + ".txt"
        s3.put_object(Bucket=bucket, Key=object_key, Body=b"hello-permission-boundary")
        attempt_deadline = time.monotonic() + 10
        while time.monotonic() < attempt_deadline:
            after_count = len(sfn.list_executions(stateMachineArn=sm_arn, maxResults=100)["executions"])
            if after_count > before_count:
                break
            time.sleep(3)
    assert after_count > before_count, "expected the permitted target to start an execution"

    # The unauthorized target's role can never gain states:StartExecution during this run
    # (a structural barrier, not a timing race), so hold a calibrated window and poll
    # repeatedly rather than sleeping once and checking only the final value — a second
    # execution must not appear even transiently.
    hold_deadline = time.monotonic() + 20
    final_count = after_count
    while time.monotonic() < hold_deadline:
        final_count = len(sfn.list_executions(stateMachineArn=sm_arn, maxResults=100)["executions"])
        assert final_count == before_count + 1, (
            f"expected exactly 1 new execution (from the permitted target), got "
            f"{final_count - before_count}"
        )
        time.sleep(3)


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


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-bkt-").lower().replace("_", "-")
    if ctx.region == "us-east-1":
        # us-east-1 is the one region where S3 rejects an explicit LocationConstraint.
        s3.create_bucket(Bucket=name)
    else:
        s3.create_bucket(Bucket=name, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, name))
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
    resp = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
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
                name=name, definition=json.dumps(definition), roleArn=role_arn, type="STANDARD"
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
