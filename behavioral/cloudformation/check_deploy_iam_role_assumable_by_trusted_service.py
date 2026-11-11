"""deploy-iam-role-assumable-by-trusted-service."""
from __future__ import annotations

import time

import botocore.exceptions

from behavioral_harness import tags

CHECK = "deploy-iam-role-assumable-by-trusted-service"
GROUP = "deploy"
SERVICES = ["cloudformation"]


@tags("axis:happy-path", "cap:c3", "cap:c7", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """An IAM role deployed via CloudFormation with a trust policy is actually
    assumable by the trusted principal -- proving the trust policy took effect
    server-side, not just that DescribeStackResources reports the role exists."""
    cfn = ctx.client("cloudformation")
    sts = ctx.client("sts")
    stack_name = ctx.unique_name("sim2real-behav-role-")
    account_id = sts.get_caller_identity()["Account"]

    template = """
AWSTemplateFormatVersion: "2010-09-09"
Resources:
  TrustRole:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Version: "2012-10-17"
        Statement:
          - Effect: Allow
            Principal:
              AWS: !Sub "arn:aws:iam::${AWS::AccountId}:root"
            Action: sts:AssumeRole
Outputs:
  RoleArn:
    Value: !GetAtt TrustRole.Arn
"""

    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=template,
        Capabilities=["CAPABILITY_IAM"],
        Tags=[{"Key": "owner", "Value": "fidelity"}],
    )
    ctx.on_cleanup(lambda: cfn.delete_stack(StackName=stack_name))

    status = _wait_stack_terminal(ctx, stack_name, timeout_s=180)
    assert status == "CREATE_COMPLETE", f"stack did not reach CREATE_COMPLETE (got {status})"

    outputs = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["Outputs"]
    role_arn = next(o["OutputValue"] for o in outputs if o["OutputKey"] == "RoleArn")
    role_name = role_arn.rsplit("/", 1)[-1]

    creds = _assume_role_with_retry(ctx, role_arn, timeout_s=60)
    assert set(["AccessKeyId", "SecretAccessKey", "SessionToken"]).issubset(creds), (
        f"AssumeRole response missing credential fields, got keys {sorted(creds)}"
    )

    assumed_sts = ctx.client(
        "sts",
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )
    identity = assumed_sts.get_caller_identity()
    assert identity["Account"] == account_id, (
        f"expected assumed-role identity in account {account_id}, got {identity['Account']}"
    )
    assert f":assumed-role/{role_name}/" in identity["Arn"], (
        f"expected an assumed-role ARN for {role_name}, got {identity['Arn']}"
    )

    # Prove the trust policy's effect is torn down with the stack, not just reported gone.
    cfn.delete_stack(StackName=stack_name)
    _wait_stack_deleted(ctx, stack_name, timeout_s=180)

    _wait_role_gone_with_retry(ctx, role_name, timeout_s=60)
    _wait_assume_role_denied_with_retry(ctx, role_arn, timeout_s=60)


_TERMINAL_STACK_STATUSES = {
    "CREATE_COMPLETE",
    "CREATE_FAILED",
    "ROLLBACK_COMPLETE",
    "ROLLBACK_FAILED",
    "UPDATE_COMPLETE",
    "UPDATE_FAILED",
    "UPDATE_ROLLBACK_COMPLETE",
    "UPDATE_ROLLBACK_FAILED",
    "DELETE_COMPLETE",
    "DELETE_FAILED",
    "IMPORT_COMPLETE",
    "IMPORT_ROLLBACK_COMPLETE",
    "IMPORT_ROLLBACK_FAILED",
}


def _wait_stack_terminal(ctx, stack_name: str, timeout_s: float = 300.0, interval_s: float = 5.0) -> str:
    cfn = ctx.client("cloudformation")
    status = None
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        if status in _TERMINAL_STACK_STATUSES:
            return status
        time.sleep(interval_s)
    raise AssertionError(f"stack {stack_name} did not reach a terminal status within {timeout_s}s (last={status})")


def _assume_role_with_retry(ctx, role_arn: str, timeout_s: float = 60.0, interval_s: float = 3.0) -> dict:
    """IAM trust-policy changes have brief propagation delay; poll AssumeRole itself
    (the observable condition we actually care about) rather than sleeping blindly."""
    sts = ctx.client("sts")
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            resp = sts.assume_role(RoleArn=role_arn, RoleSessionName="sim2real-behav-session")
            return resp["Credentials"]
        except Exception as exc:  # noqa: BLE001 - broad on purpose, retried below
            last_exc = exc
            time.sleep(interval_s)
    raise AssertionError(f"AssumeRole kept failing within {timeout_s}s: {last_exc}")


def _wait_stack_deleted(ctx, stack_name: str, timeout_s: float = 180.0, interval_s: float = 5.0) -> None:
    """CloudFormation drops a fully-deleted stack from name-based DescribeStacks
    lookup (StackId-based lookup would still show DELETE_COMPLETE); a ValidationError
    saying the stack does not exist is therefore the terminal success signal here,
    not a failure to reach one."""
    cfn = ctx.client("cloudformation")
    last_status = None
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            last_status = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        except botocore.exceptions.ClientError as exc:
            if exc.response["Error"]["Code"] == "ValidationError" and "does not exist" in exc.response["Error"]["Message"]:
                return
            raise
        if last_status == "DELETE_COMPLETE":
            return
        assert last_status == "DELETE_IN_PROGRESS", f"stack {stack_name} left delete with unexpected status {last_status}"
        time.sleep(interval_s)
    raise AssertionError(f"stack {stack_name} was not deleted within {timeout_s}s (last status={last_status})")


def _wait_role_gone_with_retry(ctx, role_name: str, timeout_s: float = 60.0, interval_s: float = 3.0) -> None:
    """get_role can briefly lag behind DELETE_COMPLETE the same way AssumeRole lags
    behind CREATE_COMPLETE; poll the observable condition rather than trusting the
    single read immediately after delete_stack returns."""
    iam = ctx.client("iam")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            iam.get_role(RoleName=role_name)
        except iam.exceptions.NoSuchEntityException:
            return
        time.sleep(interval_s)
    raise AssertionError(f"role {role_name} still exists {timeout_s}s after stack deletion")


def _wait_assume_role_denied_with_retry(ctx, role_arn: str, timeout_s: float = 60.0, interval_s: float = 3.0) -> None:
    sts = ctx.client("sts")
    deadline = time.monotonic() + timeout_s
    last_code = None
    while time.monotonic() < deadline:
        try:
            sts.assume_role(RoleArn=role_arn, RoleSessionName="sim2real-behav-session-post-delete")
        except botocore.exceptions.ClientError as exc:
            last_code = exc.response["Error"]["Code"]
            # message varies: AccessDenied names the calling principal's own ARN, which
            # differs per account and per credential, so only the code is graded.
            if last_code == "AccessDenied":
                return
        time.sleep(interval_s)
    raise AssertionError(
        f"AssumeRole for deleted role {role_arn} did not deny with AccessDenied within "
        f"{timeout_s}s (last error code={last_code})"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
