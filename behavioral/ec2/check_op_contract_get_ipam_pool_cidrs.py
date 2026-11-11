"""op-contract-get-ipam-pool-cidrs."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "op-contract-get-ipam-pool-cidrs"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:ec2-ipam")
def run(ctx) -> None:
    """GetIpamPoolCidrs lists exactly one entry, in state provisioned, for a provisioned CIDR; an unknown
    pool id fails with a NotFound or Malformed code naming IpamPool."""
    ec2 = ctx.client("ec2")

    name = ctx.unique_name("sim2real-ipam-")
    ipam = ec2.create_ipam(
        Description=name,
        OperatingRegions=[{"RegionName": ctx.region}],
        TagSpecifications=[{"ResourceType": "ipam", "Tags": [{"Key": "Name", "Value": name}]}],
    )["Ipam"]
    ipam_id = ipam["IpamId"]
    private_scope_id = ipam["PrivateDefaultScopeId"]
    ctx.on_cleanup(lambda: ec2.delete_ipam(IpamId=ipam_id, Cascade=True))

    pool_name = ctx.unique_name("sim2real-pool-")
    pool = ec2.create_ipam_pool(
        IpamScopeId=private_scope_id,
        AddressFamily="ipv4",
        Locale=ctx.region,
        Description=pool_name,
        TagSpecifications=[
            {"ResourceType": "ipam-pool", "Tags": [{"Key": "Name", "Value": pool_name}]}
        ],
    )["IpamPool"]
    pool_id = pool["IpamPoolId"]
    _wait_pool_state(ec2, pool_id, {"create-complete"})

    cidr = "10.202.0.0/16"
    ec2.provision_ipam_pool_cidr(IpamPoolId=pool_id, Cidr=cidr)

    # success-path contract: the provisioned CIDR eventually shows up as "provisioned".
    _wait_pool_cidr_state(ec2, pool_id, cidr, {"provisioned"})

    # independent read: a fresh GetIpamPoolCidrs call (not the one the wait loop last
    # made) must still show the CIDR provisioned, and show it exactly once.
    all_cidrs = ec2.get_ipam_pool_cidrs(IpamPoolId=pool_id)["IpamPoolCidrs"]
    found = [c for c in all_cidrs if c["Cidr"] == cidr]
    assert len(found) == 1, f"expected exactly one CIDR entry for {cidr}, got {all_cidrs}"
    assert found[0]["State"] == "provisioned", (
        f"expected State=provisioned on independent read, got {found[0]['State']!r}"
    )

    # error boundary: a well-formed but nonexistent pool id is rejected distinctly.
    code = _error_code(lambda: ec2.get_ipam_pool_cidrs(IpamPoolId="ipam-pool-00000000000000000"))
    _assert_invalid_id(code, "IpamPool")


def _wait_pool_state(ec2, pool_id, target_states, timeout_s=180.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    state = None
    while time.monotonic() < deadline:
        pools = ec2.describe_ipam_pools(IpamPoolIds=[pool_id])["IpamPools"]
        if pools:
            state = pools[0]["State"]
            if state in target_states:
                return state
            if state == "create-failed":
                raise AssertionError(f"pool {pool_id} entered create-failed")
        time.sleep(interval_s)
    raise AssertionError(f"pool {pool_id} never reached {target_states}, last state {state}")


def _wait_pool_cidr_state(ec2, pool_id, cidr, target_states, timeout_s=180.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    state = None
    while time.monotonic() < deadline:
        cidrs = ec2.get_ipam_pool_cidrs(IpamPoolId=pool_id)["IpamPoolCidrs"]
        for entry in cidrs:
            if entry["Cidr"] == cidr:
                state = entry["State"]
                if state in target_states:
                    return state
                if state == "failed-provision":
                    raise AssertionError(f"cidr {cidr} failed to provision")
        time.sleep(interval_s)
    raise AssertionError(f"cidr {cidr} never reached {target_states}, last state {state}")


def _error_code(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
        return None
    except ClientError as exc:
        return exc.response["Error"]["Code"]


def _assert_invalid_id(code, token):
    assert code is not None, "expected a ClientError but the call succeeded"
    assert code.endswith(".NotFound") or code.endswith(".Malformed"), (
        f"expected a *.NotFound/*.Malformed error code, got {code!r}"
    )
    assert token.lower() in code.lower(), f"expected {token!r} referenced in code, got {code!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
