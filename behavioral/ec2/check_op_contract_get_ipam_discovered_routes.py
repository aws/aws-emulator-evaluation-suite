"""op-contract-get-ipam-discovered-routes."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-get-ipam-discovered-routes"
GROUP = "error-semantics"
SERVICES = ["ec2"]
DRY_RUN_MESSAGE = "Request would have succeeded, but DryRun flag is set."


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:ec2-ipam")
def run(ctx) -> None:
    """GetIpamDiscoveredRoutes returns an empty list for a resource discovery with no BYOIP BGP
    advertisements; an unknown discovery id fails with InvalidIpamResourceDiscoveryId.NotFound and
    its exact message; DryRun fails with DryRunOperation and the standard message."""
    ec2 = ctx.client("ec2")
    resource_discovery_id = _create_ipam_with_discovery(ctx, ec2)

    resp = ec2.get_ipam_discovered_routes(
        IpamResourceDiscoveryId=resource_discovery_id, ResourceRegion=ctx.region
    )
    routes = _list_field(resp, "IpamDiscoveredRouteSet", "IpamDiscoveredRoutes")
    assert isinstance(routes, list)
    assert routes == [], "expected no BGP routes for an account with no BYOIP advertisements"

    # An empty result alone can't tell "no BYOIP advertisements" from "returns [] for
    # anything" -- break the one input a real target must validate: a well-formed but
    # nonexistent resource discovery id.
    bad_code, bad_message = _client_error(
        lambda: ec2.get_ipam_discovered_routes(
            IpamResourceDiscoveryId="ipam-res-disco-00000000000000000", ResourceRegion=ctx.region
        )
    )
    assert bad_code == "InvalidIpamResourceDiscoveryId.NotFound", f"expected NotFound, got {bad_code}"
    expected_bad_message = "The ipam-resource-discovery ID 'ipam-res-disco-00000000000000000' does not exist"
    assert bad_message == expected_bad_message, f"expected message {expected_bad_message!r}, got {bad_message!r}"

    code, message = _client_error(
        lambda: ec2.get_ipam_discovered_routes(
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
    import time
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
