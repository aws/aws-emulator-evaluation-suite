"""deploy-microsoft-ad-cfn-behaves-active."""
from __future__ import annotations

import itertools
import time

from botocore.exceptions import ClientError, WaiterError

from behavioral_harness import tags

# Zone IDs where AWS Directory Service cannot place a directory. Zone names map to different
# zones in each account, so the zones are named by ID.
_DS_UNSUPPORTED_ZONE_IDS = {"usw2-az4", "use1-az3", "use1-az5", "cac1-az4"}

CHECK = "deploy-microsoft-ad-cfn-behaves-active"
GROUP = "deploy"
SERVICES = ["ds"]


_MICROSOFT_AD_TEMPLATE = """
AWSTemplateFormatVersion: '2010-09-09'
Parameters:
  DirName:
    Type: String
  DirPassword:
    Type: String
    NoEcho: true
  VpcId:
    Type: AWS::EC2::VPC::Id
  SubnetId1:
    Type: AWS::EC2::Subnet::Id
  SubnetId2:
    Type: AWS::EC2::Subnet::Id
Resources:
  Directory:
    Type: AWS::DirectoryService::MicrosoftAD
    Properties:
      Name: !Ref DirName
      Password: !Ref DirPassword
      Edition: Standard
      VpcSettings:
        VpcId: !Ref VpcId
        SubnetIds:
          - !Ref SubnetId1
          - !Ref SubnetId2
Outputs:
  DirectoryId:
    Value: !Ref Directory
"""


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """A CFN stack deploying AWS::DirectoryService::MicrosoftAD reaches CREATE_COMPLETE with a
    real, Active directory, and deleting the stack removes the directory itself -- not merely
    DELETE_COMPLETE on the stack while the (billed) directory silently lingers."""
    vpc_id, subnet_by_az = _subnets_by_az(ctx)
    cfn = ctx.client("cloudformation")
    ds = ctx.client("ds")

    domain_name = _domain_name(ctx, "cfn")
    password = _ds_password()

    # Directory Service does not support every AZ a VPC happens to have a subnet in --
    # some AZs are capacity-constrained for it on real AWS. Try AZ pairs in order rather
    # than pinning to the first two subnets returned, so a single unsupported AZ doesn't
    # make the check fail deterministically; only the AZ-unsupported failure is retried.
    stack_name = None
    az_pairs = list(itertools.combinations(sorted(subnet_by_az), 2))
    for attempt, (az_a, az_b) in enumerate(az_pairs):
        attempt_stack_name = ctx.unique_name("sim2real-ds-cfn-")
        cfn.create_stack(
            StackName=attempt_stack_name,
            TemplateBody=_MICROSOFT_AD_TEMPLATE,
            Tags=[{"Key": "sim2real", "Value": CHECK}],
            Parameters=[
                {"ParameterKey": "DirName", "ParameterValue": domain_name},
                {"ParameterKey": "DirPassword", "ParameterValue": password},
                {"ParameterKey": "VpcId", "ParameterValue": vpc_id},
                {"ParameterKey": "SubnetId1", "ParameterValue": subnet_by_az[az_a]},
                {"ParameterKey": "SubnetId2", "ParameterValue": subnet_by_az[az_b]},
            ],
        )
        try:
            cfn.get_waiter("stack_create_complete").wait(
                StackName=attempt_stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 1800}
            )
        except WaiterError as exc:
            events = cfn.describe_stack_events(StackName=attempt_stack_name)["StackEvents"]
            reasons = [
                e.get("ResourceStatusReason", "")
                for e in events
                if "FAILED" in e["ResourceStatus"]
            ]
            last_reason = "; ".join(reasons) or str(exc)
            _delete_stack(ctx, attempt_stack_name)
            az_unsupported = any("Availability Zone" in r for r in reasons)
            if az_unsupported and attempt < len(az_pairs) - 1:
                continue
            raise AssertionError(
                f"stack create failed for every triable AZ pair; last reason: {last_reason}"
            ) from exc
        else:
            stack_name = attempt_stack_name
            break

    deleted = {"done": False}

    def _cleanup():
        if deleted["done"]:
            return
        try:
            _delete_stack(ctx, stack_name)
        except ClientError as exc:
            if not (
                (exc.response["Error"]["Code"] == "ValidationError" and "does not exist" in exc.response["Error"].get("Message", ""))
            ):
                raise

    ctx.on_cleanup(_cleanup)

    stack = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
    assert stack["StackStatus"] == "CREATE_COMPLETE", (
        f"expected CREATE_COMPLETE, got {stack['StackStatus']!r}"
    )
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}
    directory_id = outputs["DirectoryId"]

    # The CFN CREATE_COMPLETE event alone doesn't prove the directory is usable;
    # independently confirm it against the DS control plane.
    desc = _wait_for_directory_stage(ctx, directory_id, {"Active", "Failed", "Impaired"}, timeout_s=1800, interval_s=30)
    assert desc["Stage"] == "Active", f"directory {directory_id} is in stage {desc['Stage']!r}, not Active"

    limits = ds.get_directory_limits()["DirectoryLimits"]
    assert limits["CloudOnlyMicrosoftADCurrentCount"] >= 1, (
        f"expected at least 1 cloud-only MicrosoftAD directory counted, "
        f"got {limits['CloudOnlyMicrosoftADCurrentCount']}"
    )
    assert limits["CloudOnlyMicrosoftADCurrentCount"] <= limits["CloudOnlyMicrosoftADLimit"], (
        f"reported current count {limits['CloudOnlyMicrosoftADCurrentCount']} exceeds the "
        f"account's own reported limit {limits['CloudOnlyMicrosoftADLimit']}"
    )

    # Deleting the stack must remove the directory itself -- an independent read at the DS
    # control plane, not the stack's own DELETE_COMPLETE, is the proof: DescribeDirectories passes
    # through Deleting to gone: Stage=Deleted (which can stay listed for a long time), an empty list,
    # or a refusal once the id is purged.
    _delete_stack(ctx, stack_name)
    deleted["done"] = True

    _wait_for_directory_gone(ds, directory_id, timeout_s=1800, interval_s=20)

    # A second, unrelated op against the deleted directory must also fail -- proving it
    # is unusable, not merely that DescribeDirectories retains a stale historical record.
    _error_code(lambda: ds.get_snapshot_limits(DirectoryId=directory_id))


def _error_code(fn) -> str:
    """The error code of the refusal fn() must raise; a success raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"]
    raise AssertionError(f"expected an operation against the deleted directory to fail; it returned {result!r}")


def _wait_for_directory_gone(ds, directory_id, *, timeout_s: float, interval_s: float) -> None:
    """Poll DescribeDirectories until the id is gone: Stage=Deleted, an empty list, or
    EntityDoesNotExistException. Any other stage keeps polling; at the deadline it raises with it."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            descs = ds.describe_directories(DirectoryIds=[directory_id])["DirectoryDescriptions"]
        except ClientError as err:
            if err.response["Error"]["Code"] == "EntityDoesNotExistException":
                return
            raise
        if descs == []:
            return
        stage = descs[0]["Stage"]
        if stage == "Deleted":
            return
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"expected {directory_id} to be gone after stack deletion, still listed with stage "
                f"{stage!r} after {timeout_s}s"
            )
        time.sleep(interval_s)


def _ds_password() -> str:
    return "Sim2Real-Test1234!"


def _domain_name(ctx, kind: str) -> str:
    base = ctx.unique_name(f"sim2real-ds-{kind}-")
    return f"{base}.test"


def _subnets_by_az(ctx) -> tuple[str, dict[str, str]]:
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}]).get("Vpcs", [])
    if not vpcs:
        raise AssertionError(f"the run's shared network {ctx.network().vpc_id} is not visible")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}]).get("Subnets", [])
    subnets = sorted((s for s in subnets if s.get("AvailabilityZoneId") not in _DS_UNSUPPORTED_ZONE_IDS), key=lambda s: s["AvailabilityZone"])
    by_az: dict[str, str] = {}
    for s in subnets:
        by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
    if len(by_az) < 2:
        raise AssertionError("VPC has subnets in fewer than 2 distinct AZs; a directory needs 2")
    return vpc_id, by_az


def _wait_for_directory_stage(ctx, directory_id, target_stages, timeout_s, interval_s=20):
    ds = ctx.client("ds")
    deadline = time.monotonic() + timeout_s
    stage = None
    while time.monotonic() < deadline:
        desc = ds.describe_directories(DirectoryIds=[directory_id])["DirectoryDescriptions"][0]
        stage = desc["Stage"]
        if stage in target_stages:
            return desc
        time.sleep(interval_s)
    raise AssertionError(
        f"directory {directory_id} did not reach {target_stages} within {timeout_s}s (last stage={stage})"
    )


def _delete_stack(ctx, stack_name):
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)
    waiter = cfn.get_waiter("stack_delete_complete")
    waiter.wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 1800})


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
