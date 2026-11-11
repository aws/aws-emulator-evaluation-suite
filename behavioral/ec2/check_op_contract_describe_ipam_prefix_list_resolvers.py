"""op-contract-describe-ipam-prefix-list-resolvers."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-describe-ipam-prefix-list-resolvers"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeIpamPrefixListResolvers: success-path shape + DryRun error boundary."""

    ec2 = ctx.client("ec2")
    if not hasattr(ec2, "describe_ipam_prefix_list_resolvers"):
        raise AssertionError(
            "unreachable: installed botocore lacks describe_ipam_prefix_list_resolvers"
        )

    # Success path: no filter -> well-formed (possibly empty) list, no crash on shape.
    resp = ec2.describe_ipam_prefix_list_resolvers()
    assert "IpamPrefixListResolvers" in resp, f"missing key in response: {sorted(resp)}"
    resolvers = resp["IpamPrefixListResolvers"]
    assert isinstance(resolvers, list), f"expected a list, got {type(resolvers).__name__}"
    for item in resolvers:
        assert "IpamPrefixListResolverId" in item, f"resolver missing id field: {sorted(item)}"

    # Requesting a syntactically well-formed but nonexistent resolver id by
    # IpamPrefixListResolverIds is an existence lookup: it is rejected as
    # NotFound rather than silently narrowing to an empty set.
    code, message = _error(
        lambda: ec2.describe_ipam_prefix_list_resolvers(
            IpamPrefixListResolverIds=["ipam-plr-0000000000000000"]
        )
    )
    assert code == "InvalidIpamPrefixListResolverId.NotFound", f"expected NotFound, got {code!r}"
    assert message == (
        "The specified IPAM Prefix List Resolver does not exist."
    ), f"unexpected InvalidIpamPrefixListResolverId.NotFound message: {message!r}"

    # Error boundary: DryRun always yields DryRunOperation when authorized, per the
    # operation's documented contract, distinguishing it from UnauthorizedOperation.
    code, message = _error(lambda: ec2.describe_ipam_prefix_list_resolvers(DryRun=True))
    assert code == "DryRunOperation", f"expected DryRunOperation, got {code!r}"
    assert message == (
        "Request would have succeeded, but DryRun flag is set."
    ), f"unexpected DryRunOperation message: {message!r}"


def _error(fn):
    """Call fn() and return the (code, message) of the error it raises. A call
    that SUCCEEDS raises AssertionError: real AWS refuses it, so acceptance must
    not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
