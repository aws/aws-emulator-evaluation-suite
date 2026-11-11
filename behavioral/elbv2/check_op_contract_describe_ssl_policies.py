"""op-contract-describe-ssl-policies."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-describe-ssl-policies"
GROUP = "error-semantics"
SERVICES = ["elbv2"]


@tags("axis:happy-path", "cap:c5", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeSSLPolicies returns predefined policy details; an unknown policy name is rejected."""
    elbv2 = ctx.client("elbv2")

    resp = elbv2.describe_ssl_policies(Names=["ELBSecurityPolicy-2016-08"])
    policies = resp["SslPolicies"]
    assert len(policies) == 1, f"expected exactly one policy for a single named lookup, got {policies}"
    policy = policies[0]
    assert policy["Name"] == "ELBSecurityPolicy-2016-08", f"expected the requested name echoed back, got {policy['Name']!r}"
    assert len(policy["Ciphers"]) > 0, f"expected a non-empty cipher list, got {policy['Ciphers']!r}"
    assert len(policy["SslProtocols"]) > 0, f"expected a non-empty protocol list, got {policy['SslProtocols']!r}"
    assert all("Name" in c and "Priority" in c for c in policy["Ciphers"]), (
        f"expected every cipher entry to carry Name and Priority, got {policy['Ciphers']!r}"
    )

    # Sanity: listing without Names returns the full catalog including the one we probed.
    all_names = {p["Name"] for p in elbv2.describe_ssl_policies()["SslPolicies"]}
    assert "ELBSecurityPolicy-2016-08" in all_names, f"expected the probed policy in the full catalog, got {sorted(all_names)}"

    code, message = _error(
        lambda: elbv2.describe_ssl_policies(Names=["ELBSecurityPolicy-does-not-exist-2099"])
    )
    # Real AWS's ELBv2 API returns the error type WITHOUT the "Exception" suffix on the wire
    # (unlike the shape name used by the botocore model / docs).
    assert code == "SSLPolicyNotFound", f"expected not-found, got {code}"
    expected = "One or more SSL policies not found"
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _error(fn):
    """Call fn(); return its error (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to fail, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
