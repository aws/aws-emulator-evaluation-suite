"""op-contract-get-ipam-discovered-resource-cidrs."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "op-contract-get-ipam-discovered-resource-cidrs"
GROUP = "error-semantics"
SERVICES = ["ec2"]
DRY_RUN_MESSAGE = "Request would have succeeded, but DryRun flag is set."


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:ec2-ipam")
def run(ctx) -> None:
    """GetIpamDiscoveredResourceCidrs eventually reports a new VPC with its CIDR and resource type vpc
    under the IPAM's default resource discovery; DryRun fails with DryRunOperation and the standard
    message."""
    ec2 = ctx.client("ec2")
    resource_discovery_id = _create_ipam_with_discovery(ctx, ec2)

    vpc_cidr = "10.88.0.0/24"
    name = ctx.unique_name("sim2real-behav-vpc-")
    vpc = ec2.create_vpc(
        CidrBlock=vpc_cidr,
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": name}]}],
    )["Vpc"]
    vpc_id = vpc["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))

    def probe():
        from botocore.exceptions import ClientError

        # The resource-discovery ID returned by CreateIpam is not always
        # immediately queryable (eventual consistency); treat the transient
        # NotFound as "nothing discovered yet" rather than a hard failure so
        # the bounded poll below can retry until it propagates.
        try:
            resp = ec2.get_ipam_discovered_resource_cidrs(
                IpamResourceDiscoveryId=resource_discovery_id, ResourceRegion=ctx.region
            )
        except ClientError as err:
            if err.response["Error"]["Code"] == "InvalidIpamResourceDiscoveryId.NotFound":
                return []
            raise
        return _list_field(resp, "IpamDiscoveredResourceCidrSet", "IpamDiscoveredResourceCidrs")

    # IPAM resource-discovery scan latency has no documented SLA and can take several minutes, so
    # the poll allows 600 s.
    found = _poll_until(
        probe, lambda cidrs: any(c["ResourceId"] == vpc_id for c in cidrs), timeout_s=600, interval_s=20
    )
    if found is None:
        raise AssertionError("IPAM resource CIDR discovery did not complete within bounded poll")
    match = next(c for c in found if c["ResourceId"] == vpc_id)
    assert match["ResourceCidr"] == vpc_cidr, match
    assert match["ResourceType"] == "vpc", match

    code, message = _client_error(
        lambda: ec2.get_ipam_discovered_resource_cidrs(
            IpamResourceDiscoveryId=resource_discovery_id,
            ResourceRegion=ctx.region,
            DryRun=True,
        )
    )
    assert code == "DryRunOperation", f"expected DryRunOperation, got {code}"
    assert message == DRY_RUN_MESSAGE, f"expected message {DRY_RUN_MESSAGE!r}, got {message!r}"


def _list_field(resp: dict, *candidates: str) -> list:
    for key in candidates:
        if key in resp:
            return resp[key]
    for key, value in resp.items():
        if key != "ResponseMetadata" and isinstance(value, list):
            return value
    raise AssertionError(f"no list-valued field found in response: {sorted(resp)}")


def _create_ipam_with_discovery(ctx, ec2) -> str:
    name = ctx.unique_name("sim2real-behav-ipam-")
    ipam = _create_ipam_with_retry(
        ec2,
        Description=name,
        OperatingRegions=[{"RegionName": ctx.region}],
        TagSpecifications=[{"ResourceType": "ipam", "Tags": [{"Key": "Name", "Value": name}]}],
    )
    ctx.on_cleanup(lambda: ec2.delete_ipam(IpamId=ipam["IpamId"], Cascade=True))
    return ipam["DefaultResourceDiscoveryId"]


def _create_ipam_with_retry(ec2, **kwargs):
    """The per-account Ipam quota is small and shared across every behavioral
    check that creates one; a prior run's Ipam can be left over (e.g. an
    interrupted process) and exhaust it. Clean up stray sim2real Ipams and
    retry a bounded number of times before giving up."""
    from botocore.exceptions import ClientError

    last_err = None
    for attempt in range(4):
        try:
            return ec2.create_ipam(**kwargs)["Ipam"]
        except ClientError as err:
            if err.response["Error"]["Code"] != "ResourceLimitExceeded":
                raise
            last_err = err
            _delete_stray_ipams(ec2)
            time.sleep(5)
    raise AssertionError(f"account Ipam quota exhausted even after cleanup: {last_err}")


def _delete_stray_ipams(ec2) -> None:
    from botocore.exceptions import ClientError

    try:
        ipams = ec2.describe_ipams()["Ipams"]
    except ClientError:
        return
    for ipam in ipams:
        tag_map = {t["Key"]: t["Value"] for t in ipam.get("Tags", [])}
        if tag_map.get("Name", "").startswith("sim2real-behav-"):
            try:
                ec2.delete_ipam(IpamId=ipam["IpamId"], Cascade=True)
            except ClientError:
                pass


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    result = probe()
    while time.monotonic() < deadline:
        if predicate(result):
            return result
        time.sleep(interval_s)
        result = probe()
    return result if predicate(result) else None


def _client_error(fn):
    """Call fn(); return its botocore error as (code, message). An unexpected SUCCESS
    raises, so a target that accepts what AWS refuses is not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
