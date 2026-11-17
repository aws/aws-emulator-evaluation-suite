"""deploy-cfn-efs-file-system-policy-round-trip-and-delete."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cfn-efs-file-system-policy-round-trip-and-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "efs"]

_TEMPLATE = """
AWSTemplateFormatVersion: "2010-09-09"
Resources:
  MountRole:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Version: "2012-10-17"
        Statement:
          - Effect: Allow
            Principal:
              Service: ec2.amazonaws.com
            Action: sts:AssumeRole
  Fs:
    Type: AWS::EFS::FileSystem
    Properties:
      Encrypted: true
      FileSystemPolicy:
        Version: "2012-10-17"
        Statement:
          - Effect: Allow
            Principal:
              AWS: !GetAtt MountRole.Arn
            Action:
              - elasticfilesystem:ClientMount
              - elasticfilesystem:ClientWrite
            Condition:
              Bool:
                elasticfilesystem:AccessedViaMountTarget: "true"
Outputs:
  FileSystemIdRef:
    Value: !Ref Fs
  MountRoleArnGetAtt:
    Value: !GetAtt MountRole.Arn
"""


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


@tags("axis:happy-path", "cap:c1", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation AWS::EFS::FileSystem FileSystemPolicy is persisted exactly, DescribeFileSystemPolicy
    reads it back, and deleting the stack removes the file system (DescribeFileSystemPolicy then raises
    FileSystemNotFound)."""
    cfn = ctx.client("cloudformation")
    efs = ctx.client("efs")

    stack_name = ctx.unique_name("sim2real-behav-stack-")

    cfn.create_stack(StackName=stack_name, TemplateBody=_TEMPLATE, Capabilities=["CAPABILITY_IAM"])
    ctx.on_cleanup(lambda: _safe_delete_stack(cfn, stack_name))

    cfn.get_waiter("stack_create_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150}
    )

    outputs = {
        o["OutputKey"]: o["OutputValue"]
        for o in cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["Outputs"]
    }
    fs_id = outputs["FileSystemIdRef"]
    role_arn = outputs["MountRoleArnGetAtt"]
    fs_arn = efs.describe_file_systems(FileSystemId=fs_id)["FileSystems"][0]["FileSystemArn"]

    expected_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": role_arn},
                "Action": ["elasticfilesystem:ClientMount", "elasticfilesystem:ClientWrite"],
                "Resource": fs_arn,
                "Condition": {"Bool": {"elasticfilesystem:AccessedViaMountTarget": "true"}},
            }
        ],
    }

    described = efs.describe_file_system_policy(FileSystemId=fs_id)
    assert described["FileSystemId"] == fs_id, (
        f"expected DescribeFileSystemPolicy FileSystemId {fs_id!r}, got {described['FileSystemId']!r}"
    )
    described_policy = json.loads(described["Policy"])
    assert described_policy == expected_policy, (
        f"expected the stack's FileSystemPolicy, with Resource filled in as the file system's own "
        f"ARN {fs_arn!r}, read back exactly as {expected_policy!r}, got {described_policy!r}"
    )

    cfn.delete_stack(StackName=stack_name)
    cfn.get_waiter("stack_delete_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150}
    )

    code, message = _error(lambda: efs.describe_file_system_policy(FileSystemId=fs_id))
    assert code == "FileSystemNotFound", (
        f"expected FileSystemNotFound reading the file system policy after its owning stack "
        f"was deleted, got {code!r}: {message!r}"
    )
    assert message == f"File system '{fs_id}' does not exist.", f"unexpected not-found message {message!r}"


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
