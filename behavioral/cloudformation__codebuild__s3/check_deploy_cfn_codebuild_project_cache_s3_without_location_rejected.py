"""deploy-cfn-codebuild-project-cache-s3-without-location-rejected."""

from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cfn-codebuild-project-cache-s3-without-location-rejected"
GROUP = "deploy"
SERVICES = ["cloudformation", "codebuild", "s3"]

# CloudFormation's resource-handler wrapping of the service error; the request id and token vary.
_REASON = re.compile(
    r'^Resource handler returned message: "(?P<message>.*) \(Service: (?P<service>[A-Za-z0-9]+), '
    r'Status Code: (?P<status>\d+), Request ID: [^)]*\)(?: \(SDK Attempt Count: \d+\))?" '
    r"\(RequestToken: [^,]*, HandlerErrorCode: (?P<handler>[A-Za-z]+)\)$"
)


def _template(project_name: str, cache) -> str:
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "BuildRole": {
                    "Type": "AWS::IAM::Role",
                    "Properties": {
                        "AssumeRolePolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Principal": {"Service": "codebuild.amazonaws.com"},
                                    "Action": "sts:AssumeRole",
                                }
                            ],
                        }
                    },
                },
                "Project": {
                    "Type": "AWS::CodeBuild::Project",
                    "Properties": {
                        "Name": project_name,
                        "ServiceRole": {"Fn::GetAtt": ["BuildRole", "Arn"]},
                        "Source": {
                            "Type": "NO_SOURCE",
                            "BuildSpec": "version: 0.2\nphases:\n  build:\n    commands:\n      - echo hi\n",
                        },
                        "Artifacts": {"Type": "NO_ARTIFACTS"},
                        "Environment": {
                            "Type": "LINUX_CONTAINER",
                            "ComputeType": "BUILD_GENERAL1_SMALL",
                            "Image": "aws/codebuild/standard:7.0",
                        },
                        "Cache": cache,
                    },
                },
            },
        }
    )


def _create(ctx, cfn, stack_name: str, body: str) -> None:
    """CreateStack tagged with the check's own cleanup, rollback disabled so failures land as
    CREATE_FAILED rather than ROLLBACK_COMPLETE."""
    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=body,
        Capabilities=["CAPABILITY_IAM"],
        DisableRollback=True,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_name))


def _poll_until_terminal(cfn, stack_name: str, *, timeout_s: float) -> str:
    terminal = {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED"}
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        if status in terminal:
            return status
        time.sleep(2)
    raise AssertionError(
        f"stack {stack_name} did not reach a terminal status in {timeout_s}s, last {status!r}"
    )


def _failed_reason(cfn, stack_name: str, logical_id: str) -> str:
    """The ResourceStatusReason of ``logical_id``'s single CREATE_FAILED event."""
    events = []
    for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack_name):
        events.extend(page["StackEvents"])
    reasons = [
        e.get("ResourceStatusReason", "")
        for e in events
        if e["LogicalResourceId"] == logical_id and e["ResourceStatus"] == "CREATE_FAILED"
    ]
    assert len(reasons) == 1, f"expected one CREATE_FAILED event for {logical_id}, got {reasons!r}"
    return reasons[0]


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _delete_stack(cfn, stack_name: str) -> None:
    cfn.delete_stack(StackName=stack_name)
    cfn.get_waiter("stack_delete_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150}
    )


@tags("axis:rejection", "cap:c1", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """An AWS::CodeBuild::Project with Cache.Type S3 and no Location fails with CodeBuild's
    error and is never created, while the same template with a bucket/prefix Location deploys."""
    cfn = ctx.client("cloudformation")
    codebuild = ctx.client("codebuild")
    s3 = ctx.client("s3")

    good_name = ctx.unique_name("sim2real-behav-cfnok-")
    bad_name = ctx.unique_name("sim2real-behav-cfnbad-")
    good_stack = ctx.unique_name("sim2real-behav-stack-ok-")
    bad_stack = ctx.unique_name("sim2real-behav-stack-bad-")
    bucket_name = ctx.unique_name("sim2real-behav-cfnok-")

    # us-east-1 is the one region that refuses an explicit LocationConstraint.
    location = {} if ctx.region == "us-east-1" else {"LocationConstraint": ctx.region}
    bucket = s3.create_bucket(
        Bucket=bucket_name, **({"CreateBucketConfiguration": location} if location else {})
    )
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket_name))
    assert bucket["ResponseMetadata"]["HTTPStatusCode"] == 200

    # Positive control: the identical template with a valid S3 cache location, through CloudFormation.
    good_cache = {"Type": "S3", "Location": f"{bucket_name}/ci-cache"}
    _create(ctx, cfn, good_stack, _template(good_name, good_cache))
    status = _poll_until_terminal(cfn, good_stack, timeout_s=180.0)
    assert status == "CREATE_COMPLETE", f"control stack: expected CREATE_COMPLETE, got {status!r}"
    good_resp = codebuild.batch_get_projects(names=[good_name])
    assert good_resp["projectsNotFound"] == [], (
        f"positive control: expected {good_name!r} found, got not-found {good_resp['projectsNotFound']!r}"
    )
    assert good_resp["projects"][0]["cache"]["location"] == f"{bucket_name}/ci-cache", (
        f"positive control project has unexpected cache location "
        f"{good_resp['projects'][0]['cache']!r}"
    )

    # The one thing broken: Cache.Type S3 with no Location.
    bad_cache = {"Type": "S3"}
    _create(ctx, cfn, bad_stack, _template(bad_name, bad_cache))
    status = _poll_until_terminal(cfn, bad_stack, timeout_s=180.0)
    assert status == "CREATE_FAILED", f"expected stack status CREATE_FAILED, got {status!r}"
    reason = _failed_reason(cfn, bad_stack, "Project")
    match = _REASON.match(reason)
    assert match is not None, f"CREATE_FAILED reason is not a resource-handler message: {reason!r}"
    got_error = (match["message"], match["service"], match["status"], match["handler"])
    want_error = (
        "Invalid cache: location must be a valid S3 bucket, followed by slash and the prefix",
        "CodeBuild",
        "400",
        "InvalidRequest",
    )
    assert got_error == want_error, (
        f"CREATE_FAILED reason: expected {want_error!r}, got {got_error!r}"
    )

    bad_resp = codebuild.batch_get_projects(names=[bad_name])
    assert bad_resp["projects"] == [], (
        f"the invalid-cache project {bad_name!r} was minted anyway: {bad_resp['projects']}"
    )
    assert bad_resp["projectsNotFound"] == [bad_name], (
        f"expected {[bad_name]!r} in projectsNotFound, got {bad_resp['projectsNotFound']!r}"
    )

    for stack_name in (bad_stack, good_stack):
        _delete_stack(cfn, stack_name)
        got = _error(lambda stack_name=stack_name: cfn.describe_stacks(StackName=stack_name))
        assert got == ("ValidationError", f"Stack with id {stack_name} does not exist"), (
            f"DescribeStacks after the delete of {stack_name}: {got!r}"
        )
    after = codebuild.batch_get_projects(names=[good_name])
    assert after["projects"] == [] and after["projectsNotFound"] == [good_name], (
        f"the control project must be gone after its stack delete: {after!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
