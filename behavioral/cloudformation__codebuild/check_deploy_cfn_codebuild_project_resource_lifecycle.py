"""deploy-cfn-codebuild-project-resource-lifecycle."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cfn-codebuild-project-resource-lifecycle"
GROUP = "deploy"
SERVICES = ["cloudformation", "codebuild"]


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
                        },
                        "Policies": [
                            {
                                "PolicyName": "logs",
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
                "Project": {
                    "Type": "AWS::CodeBuild::Project",
                    "Properties": {
                        "Name": project_name,
                        "ServiceRole": {"Fn::GetAtt": ["BuildRole", "Arn"]},
                        "Source": {"Type": "NO_SOURCE", "BuildSpec": "version: 0.2\nphases:\n  build:\n    commands:\n      - echo hi\n"},
                        "Artifacts": {"Type": "NO_ARTIFACTS"},
                        "Environment": {
                            "Type": "LINUX_CONTAINER",
                            "ComputeType": "BUILD_GENERAL1_SMALL",
                            "Image": "aws/codebuild/standard:7.0",
                        },
                    },
                },
            },
            "Outputs": {
                "ProjectArn": {"Value": {"Fn::GetAtt": ["Project", "Arn"]}},
            },
        }
    )


@tags("axis:happy-path", "cap:c1", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation AWS::CodeBuild::Project reaches CREATE_COMPLETE, BatchGetProjects
    reflects its Source, Artifacts, Environment and every Fn::GetAtt attribute, and deleting
    the stack removes the project (it lands in BatchGetProjects' projectsNotFound)."""
    cfn = ctx.client("cloudformation")
    codebuild = ctx.client("codebuild")

    project_name = ctx.unique_name("sim2real-behav-cfnproj-")
    stack_name = ctx.unique_name("sim2real-behav-stack-")

    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=_template(project_name),
        Capabilities=["CAPABILITY_IAM"],
    )
    ctx.on_cleanup(lambda: _safe_delete_stack(cfn, stack_name))

    cfn.get_waiter("stack_create_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150}
    )

    outputs = {
        o["OutputKey"]: o["OutputValue"]
        for o in cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["Outputs"]
    }

    role_name = cfn.describe_stack_resource(StackName=stack_name, LogicalResourceId="BuildRole")[
        "StackResourceDetail"
    ]["PhysicalResourceId"]
    batch_resp = codebuild.batch_get_projects(names=[project_name])
    assert batch_resp["projectsNotFound"] == [], (
        f"expected no not-found entries, got {batch_resp['projectsNotFound']!r}"
    )
    project = batch_resp["projects"][0]
    assert project["arn"] == outputs["ProjectArn"], (
        f"expected Fn::GetAtt Project.Arn to match BatchGetProjects arn {project['arn']!r}, "
        f"got {outputs['ProjectArn']!r}"
    )
    assert project["source"]["type"] == "NO_SOURCE", (
        f"expected source.type NO_SOURCE, got {project['source']['type']!r}"
    )
    assert project["artifacts"]["type"] == "NO_ARTIFACTS", (
        f"expected artifacts.type NO_ARTIFACTS, got {project['artifacts']['type']!r}"
    )
    env = project["environment"]
    assert env["type"] == "LINUX_CONTAINER", f"expected environment.type LINUX_CONTAINER, got {env['type']!r}"
    assert env["computeType"] == "BUILD_GENERAL1_SMALL", (
        f"expected environment.computeType BUILD_GENERAL1_SMALL, got {env['computeType']!r}"
    )
    assert env["image"] == "aws/codebuild/standard:7.0", (
        f"expected environment.image aws/codebuild/standard:7.0, got {env['image']!r}"
    )

    cfn.delete_stack(StackName=stack_name)
    cfn.get_waiter("stack_delete_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150}
    )

    after = codebuild.batch_get_projects(names=[project_name])
    assert after["projects"] == [], f"expected the project gone, still described: {after['projects']}"
    assert after["projectsNotFound"] == [project_name], (
        f"expected {[project_name]!r} in projectsNotFound, got {after['projectsNotFound']!r}"
    )
    got_role = _error(lambda: ctx.client("iam").get_role(RoleName=role_name))
    assert got_role == ("NoSuchEntity", f"The role with name {role_name} cannot be found."), (
        f"GetRole on the stack's BuildRole after the stack delete: {got_role!r}"
    )


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _safe_delete_stack(cfn, stack_name: str) -> None:
    try:
        cfn.delete_stack(StackName=stack_name)
        cfn.get_waiter("stack_delete_complete").wait(
            StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150}
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "StackNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
