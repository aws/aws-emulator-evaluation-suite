"""cfn-s3-bucket-loggingconfiguration-unsupported-property-rejected-then-round-trips-with-policy."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = (
    "cfn-s3-bucket-loggingconfiguration-unsupported-property-rejected-then-round-trips-with-policy"
)
GROUP = "deploy"
SERVICES = ["cloudformation", "s3"]

_TERMINAL = frozenset(
    {
        "CREATE_COMPLETE",
        "CREATE_FAILED",
        "ROLLBACK_COMPLETE",
        "ROLLBACK_FAILED",
        "DELETE_COMPLETE",
        "DELETE_FAILED",
    }
)
_STACK_REASON = (
    "Validation failed with 1 error(s). Call DescribeEvents to retrieve the full list of "
    "issues with resource and property details, resolve each error, then retry the operation."
)


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll(ctx, probe, done, timeout_s, description, interval_s=5.0):
    """Call ``probe`` until ``done(result)``; return the result.

    A spent run budget raises TimeoutError (not graded); the wait's own deadline fails the check.
    """
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if done(last):
            return last
        if time.monotonic() > deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"{description}: the run budget ended first; not graded")
            raise AssertionError(f"{description} not met within {timeout_s:.0f}s: {last!r}")
        time.sleep(interval_s)


def _wait_stack(ctx, cfn, stack_id: str, terminal=_TERMINAL, *, timeout_s: float = 240.0) -> str:
    """Poll DescribeStacks by stack id until a status in ``terminal``; return it."""
    return _poll(
        ctx,
        lambda: cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"],
        lambda status: status in terminal,
        timeout_s,
        f"stack {stack_id} reaching one of {sorted(terminal)}",
        interval_s=2.0,
    )


def _delete_stack(ctx, cfn, stack_id: str) -> None:
    """Delete by StackId whatever state the stack is in; raise unless DELETE_COMPLETE."""
    status = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
    if status == "DELETE_COMPLETE":
        return
    if status.endswith("_IN_PROGRESS") and status != "DELETE_IN_PROGRESS":
        _wait_stack(ctx, cfn, stack_id, timeout_s=300.0)
    cfn.delete_stack(StackName=stack_id)
    status = _wait_stack(ctx, cfn, stack_id, {"DELETE_COMPLETE", "DELETE_FAILED"}, timeout_s=300.0)
    if status != "DELETE_COMPLETE":
        raise AssertionError(f"stack {stack_id!r} delete ended {status!r}")


def _stack_events(cfn, stack_id: str) -> list:
    pages = cfn.get_paginator("describe_stack_events").paginate(StackName=stack_id)
    return [e for page in pages for e in page["StackEvents"]]


def _validation_errors(cfn, stack_id: str) -> list[tuple]:
    """(logical id, type, name, status, mode, reason, path) of each VALIDATION_ERROR operation event."""
    out: list[tuple] = []
    kwargs = {"StackName": stack_id}
    while True:
        page = cfn.describe_events(**kwargs)
        out.extend(
            (
                e.get("LogicalResourceId"),
                e.get("ResourceType"),
                e.get("ValidationName"),
                e.get("ValidationStatus"),
                e.get("ValidationFailureMode"),
                e.get("ValidationStatusReason"),
                e.get("ValidationPath"),
            )
            for e in page["OperationEvents"]
            if e.get("EventType") == "VALIDATION_ERROR"
        )
        if not page.get("NextToken"):
            return out
        kwargs["NextToken"] = page["NextToken"]


def _error(fn):
    """(code, message) of the ClientError fn() raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _logdelivery_policy(target_bucket: str, source_bucket: str, account: str) -> dict:
    """The target's log-delivery bucket policy, as the template declares it."""
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "S3ServerAccessLogsPolicy",
                "Effect": "Allow",
                "Principal": {"Service": "logging.s3.amazonaws.com"},
                "Action": "s3:PutObject",
                "Resource": {"Fn::Sub": f"arn:${{AWS::Partition}}:s3:::{target_bucket}/*"},
                "Condition": {
                    "ArnLike": {
                        "aws:SourceArn": {
                            "Fn::Sub": f"arn:${{AWS::Partition}}:s3:::{source_bucket}"
                        }
                    },
                    "StringEquals": {"aws:SourceAccount": account},
                },
            }
        ],
    }


@tags(
    "axis:rejection",
    "cap:c1",
    "concern:deploy",
    "concern:negative-classes",
    "concern:representation",
    "plane:control",
)
def run(ctx) -> None:
    """An AWS::S3::Bucket LoggingConfiguration with an unsupported key fails CFN property
    validation, creating neither bucket; a valid DestinationBucketName/LogFilePrefix plus a
    log-delivery policy deploys, and GetBucketLogging and GetBucketPolicy reflect them exactly."""
    cfn = ctx.client("cloudformation")
    s3 = ctx.client("s3")
    account = ctx.account

    # The one thing broken: an unsupported key inside LoggingConfiguration.
    bad_target = ctx.unique_name("sim2real-behav-logtgt-bad-").lower()
    bad_source = ctx.unique_name("sim2real-behav-logsrc-bad-").lower()
    bad_stack_name = ctx.unique_name("sim2real-behav-logbad-stack-")
    bad_template = json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "Target": {"Type": "AWS::S3::Bucket", "Properties": {"BucketName": bad_target}},
                "Source": {
                    "Type": "AWS::S3::Bucket",
                    "DependsOn": ["Target"],
                    "Properties": {
                        "BucketName": bad_source,
                        "LoggingConfiguration": {
                            "DestinationBucketName": bad_target,
                            "LogFilePrefix": "access-logs/",
                            "Bogus": "x",
                        },
                    },
                },
            },
        }
    )
    bad_stack_id = cfn.create_stack(
        StackName=bad_stack_name,
        TemplateBody=bad_template,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["StackId"]
    ctx.on_cleanup(lambda: _delete_stack(ctx, cfn, bad_stack_id))
    bad_status = _wait_stack(ctx, cfn, bad_stack_id)
    assert bad_status == "ROLLBACK_COMPLETE", f"expected ROLLBACK_COMPLETE, got {bad_status!r}"

    events = _stack_events(cfn, bad_stack_id)
    stack_failed_reasons = [
        e.get("ResourceStatusReason", "")
        for e in events
        if e.get("LogicalResourceId") == bad_stack_name
        and e.get("ResourceStatus") == "CREATE_FAILED"
    ]
    assert stack_failed_reasons == [_STACK_REASON], (
        f"expected the stack's CREATE_FAILED reason to be {_STACK_REASON!r}, got {stack_failed_reasons!r}"
    )
    found = _validation_errors(cfn, bad_stack_id)
    want = [
        (
            "Source",
            "AWS::S3::Bucket",
            "PROPERTY_VALIDATION",
            "FAILED",
            "FAIL",
            "Unsupported property [Bogus]",
            "/Resources/Source/Properties/LoggingConfiguration",
        )
    ]
    assert found == want, f"validation errors of the create: expected {want!r}, got {found!r}"
    resources = cfn.list_stack_resources(StackName=bad_stack_id)["StackResourceSummaries"]
    assert resources == [], (
        f"a stack rejected before provisioning must report no resources, got {resources!r}"
    )
    for bucket in (bad_source, bad_target):
        got = _error(lambda b=bucket: s3.get_bucket_logging(Bucket=b))
        assert got == ("NoSuchBucket", "The specified bucket does not exist"), (
            f"the rejected stack's bucket {bucket}: {got!r}"
        )

    # Positive control: identical shape, plus a log-delivery bucket policy on the target.
    good_target = ctx.unique_name("sim2real-behav-logtgt-good-").lower()
    good_source = ctx.unique_name("sim2real-behav-logsrc-good-").lower()
    good_stack_name = ctx.unique_name("sim2real-behav-loggood-stack-")
    good_template = json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "Target": {"Type": "AWS::S3::Bucket", "Properties": {"BucketName": good_target}},
                "TargetPolicy": {
                    "Type": "AWS::S3::BucketPolicy",
                    "Properties": {
                        "Bucket": {"Ref": "Target"},
                        "PolicyDocument": _logdelivery_policy(good_target, good_source, account),
                    },
                },
                "Source": {
                    "Type": "AWS::S3::Bucket",
                    "DependsOn": ["Target", "TargetPolicy"],
                    "Properties": {
                        "BucketName": good_source,
                        "LoggingConfiguration": {
                            "DestinationBucketName": good_target,
                            "LogFilePrefix": "access-logs/",
                        },
                    },
                },
            },
        }
    )
    good_stack_id = cfn.create_stack(
        StackName=good_stack_name,
        TemplateBody=good_template,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["StackId"]
    ctx.on_cleanup(lambda: _delete_stack(ctx, cfn, good_stack_id))
    good_status = _wait_stack(ctx, cfn, good_stack_id)
    assert good_status == "CREATE_COMPLETE", f"expected CREATE_COMPLETE, got {good_status!r}"

    logging_cfg = s3.get_bucket_logging(Bucket=good_source)["LoggingEnabled"]
    assert logging_cfg["TargetBucket"] == good_target, (
        f"expected TargetBucket {good_target!r}, got {logging_cfg['TargetBucket']!r}"
    )
    assert logging_cfg["TargetPrefix"] == "access-logs/", (
        f"expected TargetPrefix 'access-logs/', got {logging_cfg['TargetPrefix']!r}"
    )
    partition = good_stack_id.split(":")[1]
    policy = json.loads(s3.get_bucket_policy(Bucket=good_target)["Policy"])
    want_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "S3ServerAccessLogsPolicy",
                "Effect": "Allow",
                "Principal": {"Service": "logging.s3.amazonaws.com"},
                "Action": "s3:PutObject",
                "Resource": f"arn:{partition}:s3:::{good_target}/*",
                "Condition": {
                    "ArnLike": {"aws:SourceArn": f"arn:{partition}:s3:::{good_source}"},
                    "StringEquals": {"aws:SourceAccount": account},
                },
            }
        ],
    }
    assert policy == want_policy, f"the target's stored bucket policy is {policy!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
