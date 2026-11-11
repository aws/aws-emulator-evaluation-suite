"""op-contract-describe-ipam-prefix-list-resolver-targets-superseded-stub."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-describe-ipam-prefix-list-resolver-targets-superseded-stub"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeIpamPrefixListResolverTargets answers with one unpaginated list, a well-formed unknown target
    ID fails with InvalidIpamPrefixListResolverTargetId.NotFound, and DryRun answers DryRunOperation
    (exact messages)."""
    ec2 = ctx.client("ec2")

    resp = ec2.describe_ipam_prefix_list_resolver_targets()
    assert resp["ResponseMetadata"]["HTTPStatusCode"] == 200
    assert "IpamPrefixListResolverTargets" in resp, f"missing key in response: {sorted(resp)}"
    targets = resp["IpamPrefixListResolverTargets"]
    assert isinstance(targets, list)
    for target in targets:
        assert "IpamPrefixListResolverTargetId" in target
        assert "IpamPrefixListResolverId" in target
    # With no MaxResults given, the service returns the full result set in one
    # page: NextToken must be absent/null, not a truncation cursor.
    assert resp.get("NextToken") is None, f"unexpected pagination cursor: {resp.get('NextToken')!r}"

    # The target-id filter is a scoping lookup, not a plain filter: a well-formed but nonexistent
    # target id is rejected as NotFound rather than silently narrowing to an empty list. This is
    # this check's own error boundary.
    code, message = _error(
        lambda: ec2.describe_ipam_prefix_list_resolver_targets(
            IpamPrefixListResolverTargetIds=["ipam-plrt-0000000000000000"]
        )
    )
    assert code == "InvalidIpamPrefixListResolverTargetId.NotFound", f"expected NotFound, got {code!r}"
    assert message == (
        "The specified IPAM Prefix List Resolver Target does not exist."
    ), f"unexpected InvalidIpamPrefixListResolverTargetId.NotFound message: {message!r}"

    code, message = _error(lambda: ec2.describe_ipam_prefix_list_resolver_targets(DryRun=True))
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
