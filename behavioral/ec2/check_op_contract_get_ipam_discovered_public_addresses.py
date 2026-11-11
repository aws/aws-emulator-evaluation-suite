"""op-contract-get-ipam-discovered-public-addresses."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "op-contract-get-ipam-discovered-public-addresses"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:ec2-ipam")
def run(ctx) -> None:
    """GetIpamDiscoveredPublicAddresses eventually reports a newly allocated Elastic IP, with its
    allocation id, under the IPAM's default resource discovery (discovery runs on a schedule, so
    the poll is long); DryRun fails with DryRunOperation and the standard message."""
    ec2 = ctx.client("ec2")
    resource_discovery_id = _create_ipam_with_discovery(ctx, ec2)

    alloc = ec2.allocate_address(
        Domain="vpc",
        TagSpecifications=[
            {
                "ResourceType": "elastic-ip",
                "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-eip-")}],
            }
        ],
    )
    public_ip = alloc["PublicIp"]
    allocation_id = alloc["AllocationId"]
    ctx.on_cleanup(lambda: ec2.release_address(AllocationId=allocation_id))

    def probe():
        resp = ec2.get_ipam_discovered_public_addresses(
            IpamResourceDiscoveryId=resource_discovery_id, AddressRegion=ctx.region
        )
        return _list_field(resp, "IpamDiscoveredPublicAddresses", "IpamDiscoveredPublicAddressSet")

    found = _poll_until(
        probe, lambda addrs: any(a["Address"] == public_ip for a in addrs), timeout_s=600, interval_s=15
    )
    if found is None:
        raise AssertionError("IPAM public address discovery did not complete within bounded poll")
    match = next(a for a in found if a["Address"] == public_ip)
    assert match["AddressAllocationId"] == allocation_id, match

    code, message = _error(
        lambda: ec2.get_ipam_discovered_public_addresses(
            IpamResourceDiscoveryId=resource_discovery_id,
            AddressRegion=ctx.region,
            DryRun=True,
        )
    )
    assert code == "DryRunOperation", f"expected DryRunOperation, got {code}"
    assert message == "Request would have succeeded, but DryRun flag is set.", message


def _list_field(resp: dict, *candidates: str) -> list:
    """The exact response key for this rarely-used operation isn't reliably
    documented across API versions; accept any of the likely names and, failing
    that, fall back to the sole list-valued field actually present."""
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


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. A success raises."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError("expected a ClientError, but the call succeeded")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
