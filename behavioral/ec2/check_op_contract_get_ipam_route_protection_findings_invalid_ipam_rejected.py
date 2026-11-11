"""op-contract-get-ipam-route-protection-findings-invalid-ipam-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-get-ipam-route-protection-findings-invalid-ipam-rejected"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:ec2-ipam")
def run(ctx) -> None:
    """GetIpamRouteProtectionFindings returns the IPAM's id and no findings for a new IPAM with no BYOIP
    routes; an unknown IPAM id fails with a NotFound or Malformed code naming Ipam."""
    ec2 = ctx.client("ec2")

    name = ctx.unique_name("sim2real-ipam-")
    ipam = ec2.create_ipam(
        Description=name,
        OperatingRegions=[{"RegionName": ctx.region}],
        TagSpecifications=[{"ResourceType": "ipam", "Tags": [{"Key": "Name", "Value": name}]}],
    )["Ipam"]
    ipam_id = ipam["IpamId"]
    ctx.on_cleanup(lambda: ec2.delete_ipam(IpamId=ipam_id, Cascade=True))

    # success-path contract: a fresh IPAM with no BYOIP CIDRs reports an empty, but
    # well-formed, set of route protection findings for itself.
    resp = ec2.get_ipam_route_protection_findings(IpamId=ipam_id)
    assert resp["IpamId"] == ipam_id, f"expected IpamId {ipam_id!r}, got {resp['IpamId']!r}"
    # EC2's query-protocol serializer omits the list member entirely when it is
    # empty (rather than sending an empty list), so treat "absent" the same as
    # "present and empty".
    findings = resp.get("RouteProtectionFindingSet", [])
    assert findings == [], f"expected no route protection findings for a fresh IPAM, got {findings!r}"

    # error boundary (overly-permissive probe): a well-formed but nonexistent IPAM id
    # must be rejected, not silently treated as "no findings".
    code = _error_code(lambda: ec2.get_ipam_route_protection_findings(IpamId="ipam-00000000000000000"))
    _assert_invalid_id(code, "Ipam")


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
