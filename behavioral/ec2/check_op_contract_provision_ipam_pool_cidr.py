"""op-contract-provision-ipam-pool-cidr."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "op-contract-provision-ipam-pool-cidr"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:ec2-ipam")
def run(ctx) -> None:
    """ProvisionIpamPoolCidr assigns a CIDR to a top-level IPAM pool and the CIDR
    eventually reaches the 'provisioned' state; provisioning against a nonexistent pool
    ID fails with InvalidIpamPoolId.NotFound and its exact message."""
    ec2 = ctx.client("ec2")
    ipam_name = ctx.unique_name("sim2real-behav-ipam-")
    ipam = ec2.create_ipam(
        Description=ipam_name,
        OperatingRegions=[{"RegionName": ctx.region}],
        TagSpecifications=[
            {"ResourceType": "ipam", "Tags": [{"Key": "Name", "Value": ipam_name}]}
        ],
    )["Ipam"]
    ipam_id = ipam["IpamId"]
    ctx.on_cleanup(lambda: ec2.delete_ipam(IpamId=ipam_id, Cascade=True))
    private_scope_id = ipam["PrivateDefaultScopeId"]

    pool_name = ctx.unique_name("sim2real-behav-pool-")
    pool = ec2.create_ipam_pool(
        IpamScopeId=private_scope_id,
        AddressFamily="ipv4",
        Description=pool_name,
        TagSpecifications=[
            {"ResourceType": "ipam-pool", "Tags": [{"Key": "Name", "Value": pool_name}]}
        ],
    )["IpamPool"]
    pool_id = pool["IpamPoolId"]
    assert _poll_until(
        lambda: ec2.describe_ipam_pools(IpamPoolIds=[pool_id])["IpamPools"][0]["State"]
        == "create-complete",
        timeout_s=60,
        interval_s=3,
    ), "IPAM pool never reached create-complete"

    cidr = "10.231.0.0/16"
    result = ec2.provision_ipam_pool_cidr(IpamPoolId=pool_id, Cidr=cidr)["IpamPoolCidr"]
    assert result["Cidr"] == cidr

    def _provisioned() -> bool:
        cidrs = ec2.get_ipam_pool_cidrs(IpamPoolId=pool_id)["IpamPoolCidrs"]
        match = next((c for c in cidrs if c["Cidr"] == cidr), None)
        return match is not None and match["State"] == "provisioned"

    assert _poll_until(_provisioned, timeout_s=90, interval_s=3), "CIDR never reached 'provisioned' state"

    err, message = _error(
        lambda: ec2.provision_ipam_pool_cidr(
            IpamPoolId="ipam-pool-00000000000000000", Cidr="10.232.0.0/16"
        )
    )
    assert err == "InvalidIpamPoolId.NotFound", f"expected InvalidIpamPoolId.NotFound, got {err}"
    assert message == "The ipam-pool ID 'ipam-pool-00000000000000000' does not exist", message


def _poll_until(probe, *, timeout_s=60.0, interval_s=3.0) -> bool:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if probe():
            return True
        time.sleep(interval_s)
    return probe()


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected SUCCESS
    raises, because an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError but the call SUCCEEDED, returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
