"""list-distributions-by-owned-resource-index-consistency."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-distributions-by-owned-resource-index-consistency"
GROUP = "data-plane"
SERVICES = ["cloudfront"]

_MANAGED_CACHING_OPTIMIZED = "658327ea-f89d-4fab-a63d-7e88639e58f6"


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll_until(probe, predicate, timeout_s=1800.0, interval_s=2.0, ctx=None):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError(f"condition (last={last!r}): the run budget ended first; not graded")
    raise AssertionError(f"condition never became true within {timeout_s}s (last={last!r})")


def _wait_distribution_deployed(ctx, dist_id, timeout_s=1800.0, interval_s=2.0, poll_ctx=None):
    cf = ctx.client("cloudfront")
    resp = _poll_until(
        lambda: cf.get_distribution(Id=dist_id),
        lambda r: r["Distribution"]["Status"] == "Deployed",
        timeout_s=timeout_s,
        interval_s=interval_s,
        ctx=poll_ctx,
    )
    return resp["ETag"]


def _delete_distribution(ctx, dist_id, etag_holder):
    cf = ctx.client("cloudfront")
    etag = etag_holder["etag"] or _wait_distribution_deployed(ctx, dist_id)
    cf.delete_distribution(Id=dist_id, IfMatch=etag)


def _launch_backing_instance(ctx):
    """Launch a minimal EC2 instance to back a CloudFront VPC origin. We only need a
    syntactically valid EC2 instance ARN in a subnet; we never send real traffic through it."""
    ec2 = ctx.client("ec2")
    subnets = ec2.describe_subnets(
        Filters=[{"Name": "subnet-id", "Values": ctx.network().subnet_ids}]
    )["Subnets"]
    if not subnets:
        raise AssertionError(
            "no shared-network subnet is available in this account/region to launch the EC2 "
            "instance backing the CloudFront VPC origin"
        )
    subnet_id = subnets[0]["SubnetId"]

    images = ec2.describe_images(
        Owners=["amazon"],
        Filters=[
            {"Name": "name", "Values": ["amzn2-ami-hvm-*-x86_64-gp2"]},
            {"Name": "state", "Values": ["available"]},
        ],
    )["Images"]
    if not images:
        raise AssertionError("no Amazon Linux 2 AMI found to launch the VPC-origin backing instance")
    images.sort(key=lambda i: i["CreationDate"], reverse=True)
    ami_id = images[0]["ImageId"]

    name = ctx.unique_name("sim2real-cf-vpco-")
    resp = ec2.run_instances(
        ImageId=ami_id,
        InstanceType="t3.micro",
        MinCount=1,
        MaxCount=1,
        SubnetId=subnet_id,
        TagSpecifications=[
            {"ResourceType": "instance", "Tags": [{"Key": "Name", "Value": name}]}
        ],
    )
    instance = resp["Instances"][0]
    instance_id = instance["InstanceId"]
    ctx.on_cleanup(lambda: ec2.terminate_instances(InstanceIds=[instance_id]))

    account_id = ctx.client("sts").get_caller_identity()["Account"]
    instance_arn = f"arn:aws:ec2:{ctx.region}:{account_id}:instance/{instance_id}"
    private_dns = instance.get("PrivateDnsName") or _poll_until(
        lambda: ec2.describe_instances(InstanceIds=[instance_id])["Reservations"][0]["Instances"][0],
        lambda i: bool(i.get("PrivateDnsName")),
        timeout_s=_budget_s(ctx, 120.0),
        ctx=ctx,
        interval_s=1.0,
    )["PrivateDnsName"]
    return instance_arn, private_dns


def _try_create_vpc_origin(cf, vpco_config):
    try:
        return cf.create_vpc_origin(VpcOriginEndpointConfig=vpco_config)
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        message = exc.response["Error"].get("Message", "")
        if code == "InvalidArgument" and "InvalidInstanceID.NotFound" in message:
            return None
        raise


def _create_vpc_origin(ctx):
    cf = ctx.client("cloudfront")
    instance_arn, private_dns = _launch_backing_instance(ctx)
    vpco_config = {
        "Name": ctx.unique_name("sim2real-vpco-"),
        "Arn": instance_arn,
        "HTTPPort": 80,
        "HTTPSPort": 443,
        "OriginProtocolPolicy": "http-only",
    }
    # A just-launched EC2 instance is not always immediately visible to CloudFront's own
    # cross-service ARN validation -- CreateVpcOrigin can answer InvalidInstanceID.NotFound
    # for a few seconds after RunInstances returns. Bounded retry on that specific error only.
    resp = _poll_until(
        lambda: _try_create_vpc_origin(cf, vpco_config),
        lambda r: r is not None,
        timeout_s=_budget_s(ctx, 60.0),
        ctx=ctx,
        interval_s=1.0,
    )
    vpc_origin = resp["VpcOrigin"]
    vpc_origin_id = vpc_origin["Id"]
    vpc_origin_arn = vpc_origin["Arn"]
    etag_holder = {"etag": None}
    ctx.on_cleanup(lambda: _delete_vpc_origin(ctx, vpc_origin_id, etag_holder))
    return vpc_origin_id, vpc_origin_arn, private_dns, etag_holder


def _wait_vpc_origin_settled(ctx, vpc_origin_id, etag_holder):
    """Reach Deployed/Failed and bank the ETag in the body, so teardown only fires DeleteVpcOrigin."""
    cf = ctx.client("cloudfront")
    deployed = _poll_until(
        lambda: cf.get_vpc_origin(Id=vpc_origin_id),
        lambda r: r["VpcOrigin"]["Status"] in ("Deployed", "Failed"),
        timeout_s=_budget_s(ctx, 1200.0),
        ctx=ctx,
        interval_s=2.0,
    )
    etag_holder["etag"] = deployed["ETag"]


def _delete_vpc_origin(ctx, vpc_origin_id, etag_holder):
    cf = ctx.client("cloudfront")
    etag = etag_holder["etag"]
    if etag is None:
        resp = _poll_until(
            lambda: cf.get_vpc_origin(Id=vpc_origin_id),
            lambda r: r["VpcOrigin"]["Status"] in ("Deployed", "Failed"),
            timeout_s=1200.0,
            interval_s=2.0,
        )
        etag = resp["ETag"]
    cf.delete_vpc_origin(Id=vpc_origin_id, IfMatch=etag)


def _create_distribution_with_vpc_origin(ctx, vpc_origin_id, domain_name):
    cf = ctx.client("cloudfront")
    resp = cf.create_distribution(
        DistributionConfig={
            "CallerReference": ctx.unique_name("sim2real-cf-"),
            "Comment": "sim2real behavioral check distribution",
            "Enabled": False,
            "Origins": {
                "Quantity": 1,
                "Items": [
                    {
                        "Id": "vpc-origin",
                        "DomainName": domain_name,
                        "VpcOriginConfig": {"VpcOriginId": vpc_origin_id},
                    }
                ],
            },
            "DefaultCacheBehavior": {
                "TargetOriginId": "vpc-origin",
                "ViewerProtocolPolicy": "allow-all",
                "CachePolicyId": _MANAGED_CACHING_OPTIMIZED,
            },
        }
    )
    dist_id = resp["Distribution"]["Id"]
    etag_holder = {"etag": None}
    ctx.on_cleanup(lambda: _delete_distribution(ctx, dist_id, etag_holder))
    return dist_id, etag_holder


def _list_by_owned_resource(cf, owned_resource_arn):
    ids = set()
    marker = None
    while True:
        kwargs = {
            "ResourceArn": owned_resource_arn,
            "MaxItems": "100",
        }
        if marker:
            kwargs["Marker"] = marker
        resp = cf.list_distributions_by_owned_resource(**kwargs)
        dlist = resp["DistributionList"]
        ids.update(item["DistributionId"] for item in dlist.get("Items", []))
        marker = dlist.get("NextMarker")
        if not marker:
            break
    return ids


# ===== check =====

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListDistributionsByOwnedResource, queried with the ARN of a VPC origin this account
    owns, enumerates only the distribution(s) that reference that specific VPC origin --
    not a distribution that references a different, unrelated VPC origin."""
    cf = ctx.client("cloudfront")
    owned_id, owned_arn, owned_dns, owned_vpco_etag = _create_vpc_origin(ctx)
    other_id, _other_arn, other_dns, other_vpco_etag = _create_vpc_origin(ctx)
    # Both origins settle concurrently; each wait banks the ETag teardown needs.
    _wait_vpc_origin_settled(ctx, owned_id, owned_vpco_etag)
    _wait_vpc_origin_settled(ctx, other_id, other_vpco_etag)

    owned_dist_id, owned_etag = _create_distribution_with_vpc_origin(ctx, owned_id, owned_dns)
    other_dist_id, other_etag = _create_distribution_with_vpc_origin(ctx, other_id, other_dns)
    owned_etag["etag"] = _wait_distribution_deployed(
        ctx, owned_dist_id, timeout_s=_budget_s(ctx, 1800.0), poll_ctx=ctx)
    other_etag["etag"] = _wait_distribution_deployed(
        ctx, other_dist_id, timeout_s=_budget_s(ctx, 1800.0), poll_ctx=ctx)

    ids = _poll_until(
        lambda: _list_by_owned_resource(cf, owned_arn),
        lambda ids: owned_dist_id in ids,
        timeout_s=_budget_s(ctx, 1800.0),
        ctx=ctx,
        interval_s=2.0,
    )
    assert owned_dist_id in ids, f"expected {owned_dist_id!r} in {ids!r}"
    assert other_dist_id not in ids, f"unrelated distribution {other_dist_id!r} leaked into {ids!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
