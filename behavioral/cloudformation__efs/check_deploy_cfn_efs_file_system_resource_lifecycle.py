"""deploy-cfn-efs-file-system-resource-lifecycle."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cfn-efs-file-system-resource-lifecycle"
GROUP = "deploy"
SERVICES = ["cloudformation", "efs"]

_TEMPLATE = """
AWSTemplateFormatVersion: "2010-09-09"
Resources:
  Fs:
    Type: AWS::EFS::FileSystem
    Properties:
      Encrypted: true
      PerformanceMode: generalPurpose
      ThroughputMode: bursting
Outputs:
  FileSystemIdRef:
    Value: !Ref Fs
  FileSystemArnGetAtt:
    Value: !GetAtt Fs.Arn
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
    """A CloudFormation AWS::EFS::FileSystem reaches CREATE_COMPLETE, DescribeFileSystems
    reflects its Encrypted, PerformanceMode, ThroughputMode and GetAtt attribute, and
    deleting the stack removes it (DescribeFileSystems then raises FileSystemNotFound)."""
    cfn = ctx.client("cloudformation")
    efs = ctx.client("efs")

    stack_name = ctx.unique_name("sim2real-behav-stack-")

    cfn.create_stack(StackName=stack_name, TemplateBody=_TEMPLATE)
    ctx.on_cleanup(lambda: _safe_delete_stack(cfn, stack_name))

    cfn.get_waiter("stack_create_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150}
    )

    outputs = {
        o["OutputKey"]: o["OutputValue"]
        for o in cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["Outputs"]
    }
    fs_id = outputs["FileSystemIdRef"]

    fs = efs.describe_file_systems(FileSystemId=fs_id)["FileSystems"][0]
    assert fs["Encrypted"] is True, f"expected Encrypted True, got {fs['Encrypted']!r}"
    assert fs["PerformanceMode"] == "generalPurpose", (
        f"expected PerformanceMode generalPurpose, got {fs['PerformanceMode']!r}"
    )
    assert fs["ThroughputMode"] == "bursting", f"expected ThroughputMode bursting, got {fs['ThroughputMode']!r}"
    assert fs["FileSystemArn"] == outputs["FileSystemArnGetAtt"], (
        f"expected Fn::GetAtt Fs.Arn to match DescribeFileSystems FileSystemArn "
        f"{fs['FileSystemArn']!r}, got {outputs['FileSystemArnGetAtt']!r}"
    )

    cfn.delete_stack(StackName=stack_name)
    cfn.get_waiter("stack_delete_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150}
    )

    code, message = _error(lambda: efs.describe_file_systems(FileSystemId=fs_id))
    assert code == "FileSystemNotFound", (
        f"expected FileSystemNotFound reading the file system after its owning stack "
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
