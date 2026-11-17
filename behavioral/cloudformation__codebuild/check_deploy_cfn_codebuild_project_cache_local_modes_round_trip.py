"""deploy-cfn-codebuild-project-cache-local-modes-round-trip."""

from __future__ import annotations

import json
import time


from behavioral_harness import tags

CHECK = "deploy-cfn-codebuild-project-cache-local-modes-round-trip"
GROUP = "deploy"
SERVICES = ["cloudformation", "codebuild"]

_TERMINAL = frozenset(
    {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "DELETE_COMPLETE", "DELETE_FAILED"}
)
_MODES = ["LOCAL_DOCKER_LAYER_CACHE", "LOCAL_CUSTOM_CACHE"]


def _template(project_name: str) -> str:
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
                            "PrivilegedMode": True,
                        },
                        "Cache": {"Type": "LOCAL", "Modes": _MODES},
                    },
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


def _delete_stack(cfn, stack_name: str) -> None:
    cfn.delete_stack(StackName=stack_name)
    cfn.get_waiter("stack_delete_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150}
    )


@tags("axis:happy-path", "cap:c1", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation AWS::CodeBuild::Project with Cache.Type LOCAL and two local cache
    modes reads back through BatchGetProjects with the exact mode list, and deleting the
    stack removes the project."""
    cfn = ctx.client("cloudformation")
    codebuild = ctx.client("codebuild")

    project_name = ctx.unique_name("sim2real-behav-cfnlocal-")
    stack_name = ctx.unique_name("sim2real-behav-stack-")

    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=_template(project_name),
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
    assert project["cache"]["type"] == "LOCAL", (
        f"expected cache.type LOCAL, got {project['cache']['type']!r}"
    )
    assert project["cache"]["modes"] == _MODES, (
        f"expected cache.modes {_MODES!r}, got {project['cache']['modes']!r}"
    )

    _delete_stack(cfn, stack_name)
    after = codebuild.batch_get_projects(names=[project_name])
    assert after["projects"] == [], (
        f"expected the project gone, still described: {after['projects']}"
    )
    assert after["projectsNotFound"] == [project_name], (
        f"expected {[project_name]!r} in projectsNotFound, got {after['projectsNotFound']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
