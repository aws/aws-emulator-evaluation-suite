"""resource-policy-delete-nonexistent-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "resource-policy-delete-nonexistent-rejected"
GROUP = "error-semantics"
SERVICES = ["cloudfront"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteResourcePolicy and GetResourcePolicy on a VPC origin with no policy succeed (a no-op, not
    EntityNotFound); once a policy is attached it round-trips, and the same delete removes it."""
    cf = ctx.client("cloudfront")
    origin = _create_vpc_origin(ctx)
    own_account = ctx.client("sts").get_caller_identity()["Account"]

    # DeleteResourcePolicy on a resource that never had a policy attached succeeds.
    cf.delete_resource_policy(ResourceArn=origin["arn"])  # must not raise

    # GetResourcePolicy on the same never-attached resource likewise succeeds, and
    # reports no policy of ours.
    never_attached = cf.get_resource_policy(ResourceArn=origin["arn"])
    assert "sim2realCrossAccountRead" not in (never_attached.get("PolicyDocument") or ""), (
        f"expected no policy attached yet, got {never_attached.get('PolicyDocument')!r}"
    )

    # Positive control. CloudFront rejects a nonexistent principal account, so grant our own.
    policy_document = json.dumps(_sample_policy(origin["arn"], own_account))
    cf.put_resource_policy(ResourceArn=origin["arn"], PolicyDocument=policy_document)
    stored = json.loads(cf.get_resource_policy(ResourceArn=origin["arn"])["PolicyDocument"])
    assert stored == json.loads(policy_document), f"expected the put policy to round-trip, got {stored!r}"

    # The same delete now removes a real policy, so the earlier no-op was not a blanket success.
    cf.delete_resource_policy(ResourceArn=origin["arn"])
    reverted = cf.get_resource_policy(ResourceArn=origin["arn"])
    assert "sim2realCrossAccountRead" not in (reverted.get("PolicyDocument") or ""), (
        f"expected the attached policy to be gone after delete, got {reverted.get('PolicyDocument')!r}"
    )


def _sample_policy(resource_arn: str, principal_account: str) -> dict:
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "sim2realCrossAccountRead",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{principal_account}:root"},
                "Action": "cloudfront:GetVpcOrigin",
                "Resource": resource_arn,
            }
        ],
    }


# Zone IDs where CloudFront does not support VPC origins (CloudFront Developer Guide, "Supported AWS
# Regions for VPC origins"); zone IDs, unlike zone names, are the same in every account.
_VPC_ORIGIN_UNSUPPORTED_ZONE_IDS = frozenset({"use1-az3", "usw1-az2", "apne1-az3", "cac1-az3"})


def _create_vpc_origin(ctx) -> dict[str, str]:
    """Wrap an internal ALB in the check's network in a VPC origin; return its id and ARN.

    The resource-policy operations accept only VPC origin ARNs, and CreateVpcOrigin needs a real ALB."""
    ec2 = ctx.client("ec2")
    elbv2 = ctx.client("elbv2")
    cf = ctx.client("cloudfront")
    name = ctx.unique_name("sim2real-vpco-")

    default_vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not default_vpcs:
        raise AssertionError("the check's network VPC is not available to host a VPC-origin ALB")
    vpc_id = default_vpcs[0]["VpcId"]

    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    by_az: dict[str, str] = {}
    for s in subnets:
        if s.get("AvailabilityZoneId") in _VPC_ORIGIN_UNSUPPORTED_ZONE_IDS:
            continue
        by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
    subnet_ids = list(by_az.values())[:2]
    if len(subnet_ids) < 2:
        raise AssertionError("the check's network lacks subnets in >=2 supported AZs required for an ALB")

    sg = ec2.create_security_group(
        GroupName=name,
        Description="sim2real behavioral probe SG",
        VpcId=vpc_id,
        TagSpecifications=[
            {"ResourceType": "security-group", "Tags": [{"Key": "Name", "Value": name}]}
        ],
    )
    sg_id = sg["GroupId"]
    ctx.on_cleanup(lambda: _delete_security_group_when_free(ec2, sg_id))

    lb = elbv2.create_load_balancer(
        Name=name,
        Subnets=subnet_ids,
        SecurityGroups=[sg_id],
        Scheme="internal",
        Type="application",
        IpAddressType="ipv4",
        Tags=[{"Key": "Name", "Value": name}],
    )["LoadBalancers"][0]
    lb_arn = lb["LoadBalancerArn"]
    ctx.on_cleanup(lambda: _ignore_not_found(
        lambda: elbv2.delete_load_balancer(LoadBalancerArn=lb_arn), "LoadBalancerNotFound"
    ))

    resp = cf.create_vpc_origin(
        VpcOriginEndpointConfig={
            "Name": name,
            "Arn": lb_arn,
            "HTTPPort": 80,
            "HTTPSPort": 443,
            "OriginProtocolPolicy": "https-only",
            "OriginSslProtocols": {"Quantity": 1, "Items": ["TLSv1.2"]},
        }
    )
    vpc_origin = resp["VpcOrigin"]
    vo_id = vpc_origin["Id"]
    arn = vpc_origin["Arn"]
    ctx.on_cleanup(lambda: _delete_vpc_origin(ctx, vo_id))
    # The resource-policy operations fail with IllegalDelete until the origin is fully
    # Deployed; merely leaving "Deploying" is not enough.
    _wait_vpc_origin_deployed(ctx, vo_id)
    return {"id": vo_id, "arn": arn}


def _wait_vpc_origin_deployed(ctx, vo_id: str, timeout_s: float = 1500.0, interval_s: float = 15.0) -> None:
    cf = ctx.client("cloudfront")
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = cf.get_vpc_origin(Id=vo_id)["VpcOrigin"]["Status"]
        if status == "Deployed":
            return
        time.sleep(interval_s)
    raise AssertionError(f"vpc origin {vo_id} never reached Deployed within {timeout_s}s (last={status!r})")


def _ignore_not_found(fn, *not_found: str) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in not_found:
            raise


def _delete_vpc_origin(ctx, vo_id: str, timeout_s: float = 600.0) -> None:
    cf = ctx.client("cloudfront")
    deadline = time.monotonic() + timeout_s
    etag = None
    while time.monotonic() < deadline:
        try:
            current = cf.get_vpc_origin(Id=vo_id)
        except ClientError as err:
            if err.response["Error"]["Code"] != "EntityNotFound":
                raise
            return
        etag = current["ETag"]
        status = current["VpcOrigin"]["Status"]
        if status not in ("Creating", "InProgress", "Deploying"):
            break
        time.sleep(2)
    if etag is None:
        return
    # A stale ETag, a still-deploying origin (IllegalDelete) or a lingering reference (...InUse)
    # clears on its own: re-read the ETag and retry to a deadline.
    delete_deadline = time.monotonic() + 120.0
    while time.monotonic() < delete_deadline:
        try:
            cf.delete_vpc_origin(Id=vo_id, IfMatch=etag)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "EntityNotFound":
                return
            if (code not in ("InvalidIfMatchVersion", "PreconditionFailed", "IllegalDelete")
                    and "InUse" not in code):
                raise
        time.sleep(2)
        try:
            etag = cf.get_vpc_origin(Id=vo_id)["ETag"]
        except ClientError as err:
            if err.response["Error"]["Code"] != "EntityNotFound":
                raise
            return
    raise AssertionError(f"DeleteVpcOrigin({vo_id}) still refused after 120 s of retries")


def _delete_security_group_when_free(ec2, sg_id, timeout_s=900.0, interval_s=15.0):
    """Delete a security group once the ENIs still holding it are released (DependencyViolation)."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ec2.delete_security_group(GroupId=sg_id)
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "InvalidGroup.NotFound":
                return
            if code != "DependencyViolation" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
