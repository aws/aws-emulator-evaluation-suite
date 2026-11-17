"""deploy-cfn-codebuild-project-customer-kms-encryption-key-round-trip."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cfn-codebuild-project-customer-kms-encryption-key-round-trip"
GROUP = "deploy"
SERVICES = ["cloudformation", "codebuild", "kms"]

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
_DELETE_TERMINAL = frozenset({"DELETE_COMPLETE", "DELETE_FAILED"})
_KEY_DESCRIPTION = "sim2real codebuild project encryption key"
_PENDING_DAYS = 7


def _key_policy():
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "EnableRoot",
                "Effect": "Allow",
                "Principal": {
                    "AWS": {"Fn::Sub": "arn:${AWS::Partition}:iam::${AWS::AccountId}:root"}
                },
                "Action": "kms:*",
                "Resource": "*",
            }
        ],
    }


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
                "ProjectKey": {
                    "Type": "AWS::KMS::Key",
                    "Properties": {
                        "Description": _KEY_DESCRIPTION,
                        "PendingWindowInDays": _PENDING_DAYS,
                        "KeyPolicy": _key_policy(),
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
                        "EncryptionKey": {"Fn::GetAtt": ["ProjectKey", "Arn"]},
                    },
                    "DependsOn": ["ProjectKey"],
                },
            },
            "Outputs": {
                "ProjectArn": {"Value": {"Fn::GetAtt": ["Project", "Arn"]}},
                "KeyArn": {"Value": {"Fn::GetAtt": ["ProjectKey", "Arn"]}},
            },
        }
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


def _stack_status(cfn, stack_id: str) -> str:
    """The stack's status read by StackId; the exact not-found pair reads as DELETE_COMPLETE."""
    try:
        return cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
    except ClientError as exc:
        err = exc.response["Error"]
        if (err.get("Code"), err.get("Message")) == (
            "ValidationError",
            f"Stack with id {stack_id} does not exist",
        ):
            return "DELETE_COMPLETE"
        raise


def _wait_stack(ctx, cfn, stack_id: str, terminal, *, timeout_s: float) -> str:
    """The stack's status once it is in ``terminal``, polled against a capped deadline."""
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = _stack_status(cfn, stack_id)
        if status in terminal:
            return status
        time.sleep(2)
    if _budget_spent(ctx):
        raise TimeoutError(f"stack {stack_id}: the run budget ended first; not graded")
    raise AssertionError(
        f"stack {stack_id} not in {sorted(terminal)} in {timeout_s}s, last {status!r}"
    )


def _delete_stack(ctx, cfn, stack_id: str) -> None:
    """Delete the stack whatever state it is in, and raise unless it reaches DELETE_COMPLETE."""
    cfn.delete_stack(StackName=stack_id)
    status = _wait_stack(ctx, cfn, stack_id, _DELETE_TERMINAL, timeout_s=300.0)
    if status != "DELETE_COMPLETE":
        raise RuntimeError(f"stack {stack_id} ended {status!r}, not DELETE_COMPLETE")


@tags("axis:happy-path", "cap:c1", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation AWS::CodeBuild::Project with EncryptionKey set to a customer KMS key
    reads back that key's exact ARN through BatchGetProjects, and deleting the stack removes the
    project and schedules the key's deletion with the template's 7-day window."""
    cfn = ctx.client("cloudformation")
    codebuild = ctx.client("codebuild")
    kms = ctx.client("kms")

    project_name = ctx.unique_name("sim2real-behav-cfnenc-")
    stack_name = ctx.unique_name("sim2real-behav-stack-")

    stack_id = cfn.create_stack(
        StackName=stack_name,
        TemplateBody=_template(project_name),
        Capabilities=["CAPABILITY_IAM"],
    )["StackId"]
    ctx.on_cleanup(lambda: _delete_stack(ctx, cfn, stack_id))

    status = _wait_stack(ctx, cfn, stack_id, _TERMINAL, timeout_s=180.0)
    assert status == "CREATE_COMPLETE", f"stack ended {status!r}"

    outputs = {
        o["OutputKey"]: o["OutputValue"]
        for o in cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["Outputs"]
    }

    batch_resp = codebuild.batch_get_projects(names=[project_name])
    assert batch_resp["projectsNotFound"] == [], (
        f"expected no not-found entries, got {batch_resp['projectsNotFound']!r}"
    )
    project = batch_resp["projects"][0]
    assert project["arn"] == outputs["ProjectArn"], (
        f"GetAtt Project.Arn {outputs['ProjectArn']!r} != BatchGetProjects arn {project['arn']!r}"
    )
    assert project["encryptionKey"] == outputs["KeyArn"], (
        f"expected encryptionKey {outputs['KeyArn']!r}, got {project['encryptionKey']!r}"
    )
    key = kms.describe_key(KeyId=outputs["KeyArn"])["KeyMetadata"]
    assert (key["KeyState"], key["Description"]) == ("Enabled", _KEY_DESCRIPTION), (
        f"expected the project's key Enabled with the template's Description, got {key!r}"
    )

    _delete_stack(ctx, cfn, stack_id)
    after = codebuild.batch_get_projects(names=[project_name])
    assert after["projects"] == [], (
        f"expected the project gone, still described: {after['projects']}"
    )
    assert after["projectsNotFound"] == [project_name], (
        f"expected {[project_name]!r} in projectsNotFound, got {after['projectsNotFound']!r}"
    )
    key = kms.describe_key(KeyId=outputs["KeyArn"])["KeyMetadata"]
    got = (key["KeyState"], key.get("PendingDeletionWindowInDays"))
    # DescribeKey reports PendingDeletionWindowInDays only for a pending replica deletion.
    assert got == ("PendingDeletion", None), (
        f"expected the stack-deleted key PendingDeletion with no replica window, got {got!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
