"""deploy-cfn-codebuild-project-cache-s3-mode-round-trip."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cfn-codebuild-project-cache-s3-mode-round-trip"
GROUP = "deploy"
SERVICES = ["cloudformation", "codebuild", "s3"]

_TERMINAL = frozenset(
    {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "DELETE_COMPLETE", "DELETE_FAILED"}
)


def _template(project_name: str, bucket_name: str, prefix: str) -> str:
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
                "CacheBucket": {
                    "Type": "AWS::S3::Bucket",
                    "Properties": {"BucketName": bucket_name},
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
                        "Cache": {
                            "Type": "S3",
                            "Location": {"Fn::Sub": f"${{CacheBucket}}/{prefix}"},
                        },
                    },
                    "DependsOn": ["CacheBucket"],
                },
            },
            "Outputs": {
                "ProjectArn": {"Value": {"Fn::GetAtt": ["Project", "Arn"]}},
            },
        }
    )


def _poll_until_terminal(cfn, stack_name: str, *, timeout_s: float) -> str:
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        if status in _TERMINAL:
            return status
        time.sleep(2)
    raise AssertionError(
        f"stack {stack_name} did not reach a terminal status in {timeout_s}s, last {status!r}"
    )


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


@tags("axis:happy-path", "cap:c1", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation AWS::CodeBuild::Project with Cache.Type S3 reads back through
    BatchGetProjects with the exact bucket/prefix location, and deleting the stack removes
    both the project and the cache bucket."""
    cfn = ctx.client("cloudformation")
    codebuild = ctx.client("codebuild")
    s3 = ctx.client("s3")

    project_name = ctx.unique_name("sim2real-behav-cfncache-")
    bucket_name = ctx.unique_name("sim2real-behav-cfncache-")
    stack_name = ctx.unique_name("sim2real-behav-stack-")
    prefix = "ci-cache"

    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=_template(project_name, bucket_name, prefix),
        Capabilities=["CAPABILITY_IAM"],
    )
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_name))

    status = _poll_until_terminal(cfn, stack_name, timeout_s=180.0)
    assert status == "CREATE_COMPLETE", f"stack ended {status!r}"

    outputs = {
        o["OutputKey"]: o["OutputValue"]
        for o in cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["Outputs"]
    }

    batch_resp = codebuild.batch_get_projects(names=[project_name])
    assert batch_resp["projectsNotFound"] == [], (
        f"expected no not-found entries, got {batch_resp['projectsNotFound']!r}"
    )
    project = batch_resp["projects"][0]
    assert project["arn"] == outputs["ProjectArn"], (
        f"GetAtt Project.Arn {outputs['ProjectArn']!r} != BatchGetProjects arn {project['arn']!r}"
    )
    want_location = f"{bucket_name}/{prefix}"
    assert project["cache"]["type"] == "S3", (
        f"expected cache.type S3, got {project['cache']['type']!r}"
    )
    assert project["cache"]["location"] == want_location, (
        f"expected cache.location {want_location!r}, got {project['cache']['location']!r}"
    )

    _delete_stack(cfn, stack_name)
    after = codebuild.batch_get_projects(names=[project_name])
    assert after["projects"] == [], (
        f"expected the project gone, still described: {after['projects']}"
    )
    assert after["projectsNotFound"] == [project_name], (
        f"expected {[project_name]!r} in projectsNotFound, got {after['projectsNotFound']!r}"
    )
    got_bucket = _error(lambda: s3.head_bucket(Bucket=bucket_name))
    assert got_bucket == ("404", "Not Found"), (
        f"HeadBucket on the stack-deleted cache bucket: {got_bucket!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
