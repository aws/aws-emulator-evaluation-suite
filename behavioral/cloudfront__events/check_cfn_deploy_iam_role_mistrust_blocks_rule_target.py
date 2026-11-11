"""cfn-deploy-iam-role-mistrust-blocks-rule-target."""

from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-deploy-iam-role-mistrust-blocks-rule-target"
GROUP = "deployment-order"
SERVICES = ["cloudfront", "events"]

# CloudFront is a global service: CloudTrail records its API calls in us-east-1 and the
# "AWS API Call via CloudTrail" events derived from them reach only us-east-1's default bus, and
# only while a trail is logging there, so the trail, stack and trigger are pinned there. This
# literal names CloudFront's CloudTrail region; it is not a pinned target region.
_EVENT_REGION = "us-east-1"
_BUCKET_DRAIN_BUDGET_S = 60.0
_DELIVERY_BUDGET_S = 600.0
_ROUND_INTERVAL_S = 30.0

_PASS_STATE_DEFINITION = {
    "StartAt": "Done",
    "States": {"Done": {"Type": "Pass", "End": True}},
}


@tags(
    "axis:negative-delivery",
    "cap:c3",
    "cap:c4",
    "cap:c7",
    "concern:deploy",
    "concern:e2e",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """A rule target RoleArn whose trust policy omits events.amazonaws.com is never assumed, so its
    state machine never executes for a matched CloudFront event, while a sibling target in the SAME
    rule with a correctly trusted role executes for the same trigger."""
    _start_trail(ctx)

    template = json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "SfnExecRole": {
                    "Type": "AWS::IAM::Role",
                    "Properties": {
                        "AssumeRolePolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Principal": {"Service": "states.amazonaws.com"},
                                    "Action": "sts:AssumeRole",
                                }
                            ],
                        }
                    },
                },
                "GoodStateMachine": {
                    "Type": "AWS::StepFunctions::StateMachine",
                    "Properties": {
                        "RoleArn": {"Fn::GetAtt": ["SfnExecRole", "Arn"]},
                        "DefinitionString": json.dumps(_PASS_STATE_DEFINITION),
                    },
                },
                "BadStateMachine": {
                    "Type": "AWS::StepFunctions::StateMachine",
                    "Properties": {
                        "RoleArn": {"Fn::GetAtt": ["SfnExecRole", "Arn"]},
                        "DefinitionString": json.dumps(_PASS_STATE_DEFINITION),
                    },
                },
                # Correctly trusts events.amazonaws.com — this is the in-file positive control.
                "GoodInvokeRole": {
                    "Type": "AWS::IAM::Role",
                    "Properties": {
                        "AssumeRolePolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Principal": {"Service": "events.amazonaws.com"},
                                    "Action": "sts:AssumeRole",
                                }
                            ],
                        },
                        "Policies": [
                            {
                                "PolicyName": "start-execution",
                                "PolicyDocument": {
                                    "Version": "2012-10-17",
                                    "Statement": [
                                        {
                                            "Effect": "Allow",
                                            "Action": "states:StartExecution",
                                            "Resource": {"Ref": "GoodStateMachine"},
                                        }
                                    ],
                                },
                            }
                        ],
                    },
                },
                # Same StartExecution permission, but the trust policy omits
                # events.amazonaws.com (trusts ec2 instead) — EventBridge can never assume it.
                "BadInvokeRole": {
                    "Type": "AWS::IAM::Role",
                    "Properties": {
                        "AssumeRolePolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Principal": {"Service": "ec2.amazonaws.com"},
                                    "Action": "sts:AssumeRole",
                                }
                            ],
                        },
                        "Policies": [
                            {
                                "PolicyName": "start-execution",
                                "PolicyDocument": {
                                    "Version": "2012-10-17",
                                    "Statement": [
                                        {
                                            "Effect": "Allow",
                                            "Action": "states:StartExecution",
                                            "Resource": {"Ref": "BadStateMachine"},
                                        }
                                    ],
                                },
                            }
                        ],
                    },
                },
                "Rule": {
                    "Type": "AWS::Events::Rule",
                    "Properties": {
                        "EventPattern": {
                            "source": ["aws.cloudfront"],
                            "detail-type": ["AWS API Call via CloudTrail"],
                            "detail": {
                                "eventSource": ["cloudfront.amazonaws.com"],
                                "eventName": ["CreateOriginAccessControl"],
                            },
                        },
                        "State": "ENABLED",
                        "Targets": [
                            {
                                "Id": "good-target",
                                "Arn": {"Ref": "GoodStateMachine"},
                                "RoleArn": {"Fn::GetAtt": ["GoodInvokeRole", "Arn"]},
                            },
                            {
                                "Id": "bad-target",
                                "Arn": {"Ref": "BadStateMachine"},
                                "RoleArn": {"Fn::GetAtt": ["BadInvokeRole", "Arn"]},
                            },
                        ],
                    },
                },
            },
            "Outputs": {
                "GoodStateMachineArn": {"Value": {"Ref": "GoodStateMachine"}},
                "BadStateMachineArn": {"Value": {"Ref": "BadStateMachine"}},
            },
        }
    )

    deployed = _deploy_cfn(ctx, template, timeout_s=300.0)
    good_arn = deployed["outputs"]["GoodStateMachineArn"]
    bad_arn = deployed["outputs"]["BadStateMachineArn"]

    cloudfront = ctx.client("cloudfront", region=_EVENT_REGION)
    sfn = ctx.client("stepfunctions", region=_EVENT_REGION)

    trigger_dt = datetime.now(timezone.utc)

    def _new_executions(arn: str):
        execs = sfn.list_executions(stateMachineArn=arn).get("executions", [])
        return [e for e in execs if e["startDate"] > trigger_dt]

    def _create_oac():
        oac_id = cloudfront.create_origin_access_control(
            OriginAccessControlConfig={
                "Name": ctx.unique_name("sim2real-xsvc-oac-"),
                "OriginAccessControlOriginType": "s3",
                "SigningBehavior": "always",
                "SigningProtocol": "sigv4",
            }
        )["OriginAccessControl"]["Id"]

        def _cleanup_oac():
            current = cloudfront.get_origin_access_control(Id=oac_id)
            cloudfront.delete_origin_access_control(Id=oac_id, IfMatch=current["ETag"])

        ctx.on_cleanup(_cleanup_oac)

    def _await_good_execution(seen: set, what: str) -> list:
        """Trigger every round until the good target has an execution not in `seen`; a trail
        does not deliver every call (a fresh one misses its first moments), so one may be lost."""
        budget_s = min(_DELIVERY_BUDGET_S, ctx.time_left() or _DELIVERY_BUDGET_S)
        deadline = time.monotonic() + budget_s
        triggers = 0
        next_trigger = 0.0
        while True:
            if time.monotonic() >= next_trigger:
                _create_oac()
                triggers += 1
                next_trigger = time.monotonic() + _ROUND_INTERVAL_S
            matches = [e for e in _new_executions(good_arn) if e["executionArn"] not in seen]
            if matches:
                return matches
            assert time.monotonic() < deadline, (
                f"correctly-trusted RoleArn target's state machine never executed {what} for any of "
                f"{triggers} CreateOriginAccessControl calls within {budget_s:.0f}s"
            )
            time.sleep(2.0)

    # Positive control: the correctly-trusted role's target executes for the trigger.
    good_matches = _await_good_execution(set(), "for the trigger")
    good_execution_arn = good_matches[0]["executionArn"]
    good_final = _poll_until(
        lambda: sfn.describe_execution(executionArn=good_execution_arn),
        lambda d: d["status"] != "RUNNING",
        timeout_s=60.0,
        interval_s=2.0,
        description="positive-control execution reaches a terminal state",
    )
    assert good_final["status"] == "SUCCEEDED"

    # Absence by contrast: further triggers until the good target's next execution, which comes
    # after both targets were attempted for the earlier event; the mistrusted one has none.
    _await_good_execution({e["executionArn"] for e in _new_executions(good_arn)}, "for the contrast trigger")
    assert _new_executions(bad_arn) == [], (
        "state machine behind the mistrusted RoleArn executed despite events.amazonaws.com "
        "never being in its trust policy"
    )


# ===== helpers =====
_XSVC_PREFIX = "sim2real-xsvc-"
_MANAGED_TAG_KEY = "sim2real:managed"


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


def _xsvc_resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _xname(ctx: Any, kind: str) -> str:
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _start_trail(ctx):
    """A single-region us-east-1 trail recording global-service (CloudFront) management events."""
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    s3 = ctx.client("s3", region=_EVENT_REGION)
    ct = ctx.client("cloudtrail", region=_EVENT_REGION)
    bucket = _xname(ctx, "cfct")
    # us-east-1 is CreateBucket's default; a LocationConstraint naming it is itself a 400.
    s3.create_bucket(Bucket=bucket)
    ctx.on_cleanup(lambda: _drain_and_delete_bucket(s3, bucket))
    s3.put_bucket_policy(
        Bucket=bucket,
        Policy=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": "cloudtrail.amazonaws.com"},
                        "Action": "s3:GetBucketAcl",
                        "Resource": f"arn:aws:s3:::{bucket}",
                    },
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": "cloudtrail.amazonaws.com"},
                        "Action": "s3:PutObject",
                        "Resource": f"arn:aws:s3:::{bucket}/AWSLogs/{account_id}/*",
                        "Condition": {
                            "StringEquals": {"s3:x-amz-acl": "bucket-owner-full-control"}
                        },
                    },
                ],
            }
        ),
    )
    trail_arn = ct.create_trail(
        Name=_xname(ctx, "cfct"),
        S3BucketName=bucket,
        IsMultiRegionTrail=False,
        IncludeGlobalServiceEvents=True,
        TagsList=_xsvc_tags_kv(),
    )["TrailARN"]
    ctx.on_cleanup(lambda: _delete_trail_quietly(ct, trail_arn))
    ct.start_logging(Name=trail_arn)
    logging = ct.get_trail_status(Name=trail_arn).get("IsLogging")
    assert logging is True, (
        f"the trail must be logging before any trigger fires: expected True, actual {logging!r}"
    )


def _delete_trail_quietly(ct, trail_arn):
    try:
        ct.delete_trail(Name=trail_arn)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "TrailNotFoundException":
            raise


def _drain_and_delete_bucket(s3, bucket):
    """CloudTrail can land a log file after the trail is gone, so drain-then-delete in a bounded
    loop, and raise if it never converges."""
    deadline = time.monotonic() + _BUCKET_DRAIN_BUDGET_S
    while True:
        keys = []
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
            keys.extend(o["Key"] for o in page.get("Contents", []))
        for i in range(0, len(keys), 1000):
            failed = s3.delete_objects(
                Bucket=bucket, Delete={"Objects": [{"Key": k} for k in keys[i : i + 1000]]}
            ).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        try:
            s3.delete_bucket(Bucket=bucket)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "NoSuchBucket":
                return
            if code != "BucketNotEmpty":
                raise
        if time.monotonic() >= deadline:
            raise RuntimeError(f"trail bucket {bucket} not empty after drain")
        time.sleep(5.0)


def _delete_stack_and_wait(ctx, stack_name: str) -> None:
    cfn = ctx.client("cloudformation", region=_EVENT_REGION)
    cfn.delete_stack(StackName=stack_name)

    def _status():
        try:
            return cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("StackNotFoundException", "ValidationError") or (
                exc.response["Error"]["Code"] == "ValidationError"
                and "does not exist" not in exc.response["Error"]["Message"]
            ):
                raise
            return 'GONE'

    _poll_until(
        _status,
        lambda s: s in {"DELETE_COMPLETE", "GONE"},
        timeout_s=120,
        interval_s=5.0,
        description=f"delete stack {stack_name}",
    )


def _deploy_cfn(
    ctx,
    template,
    *,
    stack_name=None,
    parameters=None,
    capabilities=None,
    timeout_s=300.0,
) -> dict[str, Any]:
    ctx.verify_account_safety()
    cfn = ctx.client("cloudformation", region=_EVENT_REGION)
    name = stack_name or _xname(ctx, "stk")
    template_body = template.read_text() if isinstance(template, Path) else template
    kwargs: dict[str, Any] = {
        "StackName": name,
        "TemplateBody": template_body,
        "Tags": _xsvc_tags_kv(),
        "Capabilities": capabilities or ["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
    }
    if parameters:
        kwargs["Parameters"] = [
            {"ParameterKey": k, "ParameterValue": v} for k, v in parameters.items()
        ]
    stack_id = cfn.create_stack(**kwargs)["StackId"]
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, name))
    _poll_until(
        lambda: cfn.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"],
        lambda s: (
            s
            in {
                "CREATE_COMPLETE",
                "CREATE_FAILED",
                "ROLLBACK_COMPLETE",
                "ROLLBACK_FAILED",
            }
        ),
        timeout_s=timeout_s,
        interval_s=5.0,
        description=f"CFN stack {name}",
    )
    stack = cfn.describe_stacks(StackName=name)["Stacks"][0]
    if stack["StackStatus"] != "CREATE_COMPLETE":
        raise AssertionError(f"Stack {name} ended in {stack['StackStatus']}")
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}
    return {"stack_name": name, "stack_id": stack_id, "outputs": outputs}


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
