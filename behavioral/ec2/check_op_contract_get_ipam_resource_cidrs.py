"""op-contract-get-ipam-resource-cidrs."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "op-contract-get-ipam-resource-cidrs"
GROUP = "error-semantics"
SERVICES = ["ec2"]
_DISCOVERY_DEADLINE_S = 900.0


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:ec2-ipam")
def run(ctx) -> None:
    """GetIpamResourceCidrs eventually lists a new VPC's CIDR in the private scope as a vpc-typed entry;
    an unknown scope id fails with a NotFound or Malformed code naming IpamScope."""
    ec2 = ctx.client("ec2")

    ipam = ec2.create_ipam(
        Description=ctx.unique_name("sim2real-ipam-"),
        OperatingRegions=[{"RegionName": ctx.region}],
    )["Ipam"]
    ipam_id = ipam["IpamId"]
    private_scope_id = ipam["PrivateDefaultScopeId"]
    ctx.on_cleanup(lambda: ec2.delete_ipam(IpamId=ipam_id, Cascade=True))

    # A dedicated VPC so the check controls its CIDR precisely.
    vpc_cidr = "10.77.0.0/16"
    vpc = ec2.create_vpc(
        CidrBlock=vpc_cidr,
        TagSpecifications=[
            {
                "ResourceType": "vpc",
                "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-vpc-")}],
            }
        ],
    )["Vpc"]
    vpc_id = vpc["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))

    # success-path contract: IPAM's default resource discovery eventually surfaces the VPC's CIDR
    # under the private scope. Discovery scan latency is undocumented and can exceed ten minutes, so
    # poll with the same 900 s bound used elsewhere in this suite for the identical discovery
    # mechanism.
    left = ctx.time_left()
    discovery_s = _DISCOVERY_DEADLINE_S if left is None else min(_DISCOVERY_DEADLINE_S, left)
    found = _poll_until(
        lambda: ec2.get_ipam_resource_cidrs(
            IpamScopeId=private_scope_id, ResourceId=vpc_id
        )["IpamResourceCidrs"],
        lambda cidrs: any(c["ResourceCidr"] == vpc_cidr for c in cidrs),
        timeout_s=discovery_s,
        interval_s=2.0,
    )
    if found is None:
        raise AssertionError(
            f"IPAM did not discover VPC {vpc_id} in the private scope within {discovery_s:.0f}s; "
            "discovery scan latency is undocumented and can exceed this window"
        )
    assert any(c["ResourceType"] == "vpc" for c in found), (
        f"expected a vpc-typed entry for {vpc_id!r} in {found!r}"
    )

    # error boundary: a well-formed but nonexistent scope id is rejected distinctly.
    code = _error_code(
        lambda: ec2.get_ipam_resource_cidrs(IpamScopeId="ipam-scope-00000000000000000")
    )
    _assert_invalid_id(code, "IpamScope")


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    result = None
    while time.monotonic() < deadline:
        result = probe()
        if predicate(result):
            return result
        time.sleep(interval_s)
    return None


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
