"""deploy-ipset-cfn-behaves."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "deploy-ipset-cfn-behaves"
GROUP = "deploy"
SERVICES = ["guardduty"]

_TEMPLATE = """
AWSTemplateFormatVersion: '2010-09-09'
Parameters:
  DetectorId:
    Type: String
  Location:
    Type: String
  SetName:
    Type: String
Resources:
  MyIPSet:
    Type: AWS::GuardDuty::IPSet
    Properties:
      DetectorId: !Ref DetectorId
      Name: !Ref SetName
      Format: TXT
      Location: !Ref Location
      Activate: true
Outputs:
  IpSetId:
    Value: !Ref MyIPSet
"""


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:representation", "plane:control", "resource:account-singleton:guardduty-detector")
def run(ctx) -> None:
    """A CloudFormation-deployed IPSet reaches ACTIVE with the template's TXT format,
    location and name and is listed; deleting the stack moves it to Status DELETED and
    drops it from ListIPSets."""
    gd = ctx.client("guardduty")
    detector_id, owned_detector = _get_or_create_detector(ctx)
    if owned_detector:
        ctx.on_cleanup(lambda: gd.delete_detector(DetectorId=detector_id))

    bucket, key, location = _put_ip_list(ctx)

    set_name = ctx.unique_name("sim2real-behav-ipset-cfn-")
    stack_name, outputs = _deploy_cfn(
        ctx,
        _TEMPLATE,
        parameters=[
            {"ParameterKey": "DetectorId", "ParameterValue": detector_id},
            {"ParameterKey": "Location", "ParameterValue": location},
            {"ParameterKey": "SetName", "ParameterValue": set_name},
        ],
    )
    ip_set_id = outputs["IpSetId"]

    status = _poll_ip_set_status(gd, detector_id, ip_set_id, timeout_s=120.0)
    assert status == "ACTIVE", f"expected ACTIVE, got {status}"

    got = gd.get_ip_set(DetectorId=detector_id, IpSetId=ip_set_id)
    assert got["Format"] == "TXT"
    assert got["Location"] == location
    assert got["Name"] == set_name

    ids = gd.list_ip_sets(DetectorId=detector_id)["IpSetIds"]
    assert ip_set_id in ids

    # teardown asserted: deleting the stack must actually remove the IPSet at the
    # destination -- GuardDuty answers a deleted IPSet's GetIPSet with a terminal
    # delete status rather than a not-found error, so the status transition (not an
    # exception) is the proof.
    _delete_stack(ctx, stack_name)
    final_status = _poll_delete_status(gd, detector_id, ip_set_id)
    assert final_status == "DELETED", (
        f"expected the terminal DELETED status after stack teardown, got {final_status!r}"
    )
    remaining_ids = gd.list_ip_sets(DetectorId=detector_id).get("IpSetIds", [])
    assert ip_set_id not in remaining_ids


def _get_or_create_detector(ctx):
    from botocore.exceptions import ClientError

    gd = ctx.client("guardduty")
    existing = gd.list_detectors().get("DetectorIds", [])
    if existing:
        return existing[0], False
    try:
        detector_id = gd.create_detector(
            Enable=True,
            FindingPublishingFrequency="FIFTEEN_MINUTES",
            Tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
        )["DetectorId"]
        return detector_id, True
    except ClientError:
        existing = gd.list_detectors().get("DetectorIds", [])
        if existing:
            return existing[0], False
        raise


def _put_ip_list(ctx):
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-behav-gd-ipset-").lower().replace("_", "-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket))
    key = "ipset.txt"
    body = b"203.0.113.5/32\n198.51.100.0/24\n"
    s3.put_object(Bucket=bucket, Key=key, Body=body)
    ctx.on_cleanup(lambda: s3.delete_object(Bucket=bucket, Key=key))
    s3.put_bucket_tagging(
        Bucket=bucket,
        Tagging={"TagSet": [{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:prefix", "Value": "sim2real-behav"}]},
    )
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowGuardDutyRead",
                "Effect": "Allow",
                "Principal": {"Service": "guardduty.amazonaws.com"},
                "Action": "s3:GetObject",
                "Resource": f"arn:aws:s3:::{bucket}/{key}",
            }
        ],
    }
    import json

    s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps(policy))
    location = ctx.s3_object_url(f"https://s3.{ctx.region}.amazonaws.com/{bucket}/{key}", bucket, key)
    return bucket, key, location


def _poll_ip_set_status(gd, detector_id: str, ip_set_id: str, timeout_s: float = 120.0) -> str:
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = gd.get_ip_set(DetectorId=detector_id, IpSetId=ip_set_id)["Status"]
        if status not in ("ACTIVATING",):
            return status
        time.sleep(3)
    raise AssertionError(f"IPSet {ip_set_id} stayed ACTIVATING past {timeout_s}s (last={status})")


def _poll_delete_status(gd, detector_id: str, ip_set_id: str, timeout_s: float = 300.0) -> str:
    """Poll GetIPSet past the transient DELETE_PENDING until the terminal DELETED status."""
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = gd.get_ip_set(DetectorId=detector_id, IpSetId=ip_set_id)["Status"]
        if status == "DELETED":
            return status
        time.sleep(5)
    raise AssertionError(f"IPSet {ip_set_id} did not reach DELETED within {timeout_s}s (last={status})")


def _deploy_cfn(ctx, template_body: str, parameters=None):
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-behav-gd-ipset-")
    kwargs = {
        "StackName": stack_name,
        "TemplateBody": template_body,
        "Capabilities": ["CAPABILITY_IAM"],
        "Tags": [{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:prefix", "Value": "sim2real-behav"}],
    }
    if parameters:
        kwargs["Parameters"] = parameters
    cfn.create_stack(**kwargs)
    ctx.on_cleanup(lambda: _delete_stack(ctx, stack_name))
    cfn.get_waiter("stack_create_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 450}
    )
    resp = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
    outputs = {o["OutputKey"]: o["OutputValue"] for o in resp.get("Outputs", [])}
    return stack_name, outputs


def _delete_stack(ctx, stack_name: str) -> None:
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)
    cfn.get_waiter("stack_delete_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 450}
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
