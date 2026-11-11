"""deploy-codebuild-project-cfn-starts-build."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-codebuild-project-cfn-starts-build"
GROUP = "deploy"
SERVICES = ["codebuild"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "dp:api", "plane:data")
def run(ctx) -> None:
    """A CloudFormation-provisioned CodeBuild project runs: StartBuild returns IN_PROGRESS and
    StopBuild moves the build to STOPPED; deleting the stack then removes the project."""
    cfn = ctx.client("cloudformation")
    codebuild = ctx.client("codebuild")
    deleted = [False]

    project_name = ctx.unique_name("sim2real-cb-proj-")
    stack_name = ctx.unique_name("sim2real-cb-stack-")

    template = json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "CodeBuildRole": {
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
                        },
                        "Policies": [
                            {
                                "PolicyName": "CodeBuildLogs",
                                "PolicyDocument": {
                                    "Version": "2012-10-17",
                                    "Statement": [
                                        {
                                            "Effect": "Allow",
                                            "Action": [
                                                "logs:CreateLogGroup",
                                                "logs:CreateLogStream",
                                                "logs:PutLogEvents",
                                            ],
                                            "Resource": "*",
                                        }
                                    ],
                                },
                            }
                        ],
                    },
                },
                "CodeBuildProject": {
                    "Type": "AWS::CodeBuild::Project",
                    "Properties": {
                        "Name": project_name,
                        "ServiceRole": {"Fn::GetAtt": ["CodeBuildRole", "Arn"]},
                        "Source": {
                            "Type": "NO_SOURCE",
                            "BuildSpec": (
                                "version: 0.2\nphases:\n  build:\n    commands:\n"
                                "      - sleep 600\n"
                            ),
                        },
                        "Artifacts": {"Type": "NO_ARTIFACTS"},
                        "Environment": {
                            "Type": "LINUX_CONTAINER",
                            "ComputeType": "BUILD_GENERAL1_SMALL",
                            "Image": "aws/codebuild/standard:7.0",
                        },
                    },
                },
            },
        }
    )

    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=template,
        Capabilities=["CAPABILITY_IAM"],
    )
    ctx.on_cleanup(lambda: None if deleted[0] else _delete_stack(ctx, stack_name))

    waiter = cfn.get_waiter("stack_create_complete")
    waiter.wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    status = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
    assert status == "CREATE_COMPLETE", f"stack ended in {status}"

    # The buildspec sleeps far longer than this check runs, so the build is still running at
    # StopBuild.
    start_resp = codebuild.start_build(projectName=project_name)
    build_id = start_resp["build"]["id"]
    ctx.on_cleanup(lambda: _stop_build(codebuild, build_id))
    assert start_resp["build"]["projectName"] == project_name, (
        f"expected projectName={project_name!r}, got {start_resp['build']['projectName']!r}"
    )
    assert start_resp["build"]["buildStatus"] == "IN_PROGRESS", (
        f"expected buildStatus=IN_PROGRESS, got {start_resp['build']['buildStatus']!r}"
    )
    _poll_until(
        lambda: codebuild.batch_get_builds(ids=[build_id])["builds"][0],
        lambda b: b["buildStatus"] == "IN_PROGRESS",
        timeout_s=60,
        interval_s=2,
    )

    stop_resp = codebuild.stop_build(id=build_id)
    assert stop_resp["build"]["id"] == build_id, (
        f"expected stop_build to echo id={build_id!r}, got {stop_resp['build']['id']!r}"
    )

    final = _poll_until(
        lambda: codebuild.batch_get_builds(ids=[build_id])["builds"][0],
        lambda b: bool(b.get("buildComplete")),
        timeout_s=120,
        interval_s=5,
    )
    assert final["buildStatus"] == "STOPPED", (
        f"expected buildStatus=STOPPED after stop_build, got {final['buildStatus']!r}"
    )
    assert final["projectName"] == project_name, (
        f"expected projectName={project_name!r} on the final build record, got {final['projectName']!r}"
    )

    # Stack deletion is confirmed by a CodeBuild read, not a CloudFormation status.
    cfn.delete_stack(StackName=stack_name)
    cfn.get_waiter("stack_delete_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 300}
    )
    deleted[0] = True

    batch_resp = codebuild.batch_get_projects(names=[project_name])
    assert batch_resp["projects"] == [], (
        f"expected project {project_name!r} gone after stack delete, still described: {batch_resp['projects']}"
    )
    assert project_name in batch_resp["projectsNotFound"], (
        f"expected {project_name!r} in projectsNotFound, got {batch_resp['projectsNotFound']!r}"
    )


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last value: {last}")


def _stop_build(codebuild, build_id: str) -> None:
    """Teardown: stop the build (a no-op once it finished), tolerating only its not-found."""
    try:
        codebuild.stop_build(id=build_id)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


def _delete_stack(ctx, stack_name: str) -> None:
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)
    waiter = cfn.get_waiter("stack_delete_complete")
    waiter.wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 300})


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
