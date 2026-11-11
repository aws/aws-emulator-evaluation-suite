"""ipam-family-error-semantics."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags


def _probe_errors(client, probes):
    """Assert a batch of operations all fail with an expected error code.

    *probes* is a list of ``(client_method, kwargs, acceptable_codes)``. Every
    mismatch is collected rather than raising on the first, and operations the
    installed botocore does not know about are reported as skipped. Returns
    ``(problems, skipped)``.

    A ``ParamValidationError`` is deliberately left uncaught: it means the request
    never left the SDK, so it says nothing about the target's error semantics and
    must not be folded into ``problems`` as though it were one. It surfaces as a
    hard failure of the probe's own construction instead.
    """
    problems = []
    skipped = []
    for method, kwargs, expected in probes:
        fn = getattr(client, method, None)
        if fn is None:
            skipped.append(method)
            continue
        try:
            fn(**kwargs)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code not in expected:
                problems.append(f"{method}: expected {sorted(expected)}, got {code}")
        else:
            problems.append(f"{method}: expected {sorted(expected)} but the call SUCCEEDED")
    return problems, skipped


# Well-formed but nonexistent resource ids (17 hex chars after the prefix), so
# probes exercise NotFound semantics rather than id-format rejection.
_ABSENT = {
    "ipam": "ipam-0123456789abcdef0",
    "ipam_scope": "ipam-scope-0123456789abcdef0",
    "ipam_pool": "ipam-pool-0123456789abcdef0",
    "ipam_disco": "ipam-res-disco-0123456789abcdef0",
}

CHECK = "ipam-family-error-semantics"
GROUP = 'error-semantics'
SERVICES = ['ec2']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """IPAM create/delete operations must reject unknown IPAM/scope/pool ids."""
    ec2 = ctx.client("ec2")
    a = _ABSENT
    ipam_nf = ("InvalidIpamId.NotFound",)
    param = ("InvalidParameterValue",)

    problems, _ = _probe_errors(ec2, [
        ("create_ipam_scope", {"IpamId": a["ipam"]}, ipam_nf),
        (
            "create_ipam_pool",
            {"IpamScopeId": a["ipam_scope"], "AddressFamily": "ipv4"},
            ("InvalidIpamScopeId.NotFound",),
        ),
        ("create_ipam_external_resource_verification_token", {"IpamId": a["ipam"]}, ipam_nf),
        (
            "create_ipam_resource_discovery",
            {"OperatingRegions": [{"RegionName": "not-a-real-region"}]},
            param,
        ),
        ("delete_ipam", {"IpamId": a["ipam"]}, ipam_nf),
        ("delete_ipam_scope", {"IpamScopeId": a["ipam_scope"]}, ("InvalidIpamScopeId.NotFound",)),
        ("delete_ipam_pool", {"IpamPoolId": a["ipam_pool"]}, ("InvalidIpamPoolId.NotFound",)),
        (
            "delete_ipam_resource_discovery",
            {"IpamResourceDiscoveryId": a["ipam_disco"]},
            param + ("InvalidIpamResourceDiscoveryId.NotFound",),
        ),
    ])
    assert not problems, "unexpected IPAM error semantics:\n" + "\n".join(problems)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
