"""deploy-ipset-cfn-becomes-active-and-usable."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "deploy-ipset-cfn-becomes-active-and-usable"
GROUP = "state-machine"
SERVICES = ["guardduty"]

_TEMPLATE = """
AWSTemplateFormatVersion: '2010-09-09'
Parameters:
  IpSetLocation:
    Type: String
  IpSetName:
    Type: String
Resources:
  GDDetector:
    Type: AWS::GuardDuty::Detector
    Properties:
      Enable: true
  GDIPSet:
    Type: AWS::GuardDuty::IPSet
    Properties:
      Activate: true
      DetectorId: !Ref GDDetector
      Format: TXT
      Location: !Ref IpSetLocation
      Name: !Ref IpSetName
"""


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:deploy", "concern:representation", "plane:control", "resource:account-singleton:guardduty-detector")
def run(ctx) -> None:
    """An IPSet deployed by CloudFormation with its detector in the same stack
    reaches ACTIVE, is listed by ListIPSets and GetIPSet returns its templated
    name: GuardDuty fetched and activated the S3 list."""
    gd = ctx.client("guardduty")
    if gd.list_detectors().get("DetectorIds", []):
        raise AssertionError(
            "unreachable: GuardDuty allows only one detector per account/region and "
            "this account/region already has one (from another concurrently running "
            "check or a prior leftover) -- the CFN stack's AWS::GuardDuty::Detector "
            "resource would fail to create a second one. Re-run in a clean "
            "account/region to exercise this."
        )

    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-gd-cfn-ip-").lower()
    _create_bucket(ctx, s3, bucket)
    key = "trusted-ips.txt"
    s3.put_object(Bucket=bucket, Key=key, Body=b"192.0.2.100\n")
    ctx.on_cleanup(lambda: s3.delete_object(Bucket=bucket, Key=key))
    location = f"https://s3.amazonaws.com/{bucket}/{key}"
    ip_set_name = ctx.unique_name("sim2real-cfn-ipset-")

    stack_name = _deploy_cfn(ctx, _TEMPLATE, location, ip_set_name)
    detector_id = _physical_id(ctx, stack_name, "GDDetector")
    ip_set_id = _physical_id(ctx, stack_name, "GDIPSet")

    status = _poll_ipset_status(ctx, gd, detector_id, ip_set_id, "ACTIVE")
    assert status == "ACTIVE", f"expected ip set {ip_set_id} to reach ACTIVE, got {status!r}"

    listed = gd.list_ip_sets(DetectorId=detector_id)["IpSetIds"]
    assert ip_set_id in listed, f"expected {ip_set_id} in ListIPSets, got {listed!r}"
    got = gd.get_ip_set(DetectorId=detector_id, IpSetId=ip_set_id)
    assert got["Name"] == ip_set_name, f"expected Name={ip_set_name!r}, got {got['Name']!r}"


def _deploy_cfn(ctx, template_body: str, location: str, ip_set_name: str) -> str:
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-gd-ipset-")

    def _cleanup():
        cfn.delete_stack(StackName=stack_name)
        cfn.get_waiter("stack_delete_complete").wait(
            StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 300}
        )

    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=template_body,
        Parameters=[
            {"ParameterKey": "IpSetLocation", "ParameterValue": location},
            {"ParameterKey": "IpSetName", "ParameterValue": ip_set_name},
        ],
    )
    ctx.on_cleanup(_cleanup)
    cfn.get_waiter("stack_create_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 450}
    )
    return stack_name


def _physical_id(ctx, stack_name: str, logical_id: str) -> str:
    cfn = ctx.client("cloudformation")
    resources = cfn.describe_stack_resources(StackName=stack_name)["StackResources"]
    for resource in resources:
        if resource["LogicalResourceId"] == logical_id:
            return resource["PhysicalResourceId"]
    raise AssertionError(f"resource {logical_id} not found in stack {stack_name}")


def _create_bucket(ctx, s3, bucket: str) -> None:
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket,
            CreateBucketConfiguration={"LocationConstraint": ctx.region},
        )
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket))


def _poll_ipset_status(ctx, gd, detector_id: str, ip_set_id: str, expected: str, timeout_s: float = 90.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = gd.get_ip_set(DetectorId=detector_id, IpSetId=ip_set_id)["Status"]
        if last in (expected, "ERROR"):
            return last
        time.sleep(3.0)
    return last


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
