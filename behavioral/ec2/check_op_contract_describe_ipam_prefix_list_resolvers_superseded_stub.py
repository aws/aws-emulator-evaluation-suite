"""op-contract-describe-ipam-prefix-list-resolvers-superseded-stub."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-describe-ipam-prefix-list-resolvers-superseded-stub"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeIpamPrefixListResolvers answers 200 with one unpaginated list of resolvers carrying an ID
    and State, and DryRun answers DryRunOperation with its exact message."""
    ec2 = ctx.client("ec2")

    resp = ec2.describe_ipam_prefix_list_resolvers()
    status = resp["ResponseMetadata"]["HTTPStatusCode"]
    assert status == 200, f"expected HTTP 200, got {status!r}"
    assert "IpamPrefixListResolvers" in resp, f"missing key in response: {sorted(resp)}"
    resolvers = resp["IpamPrefixListResolvers"]
    assert isinstance(resolvers, list), f"expected a list, got {type(resolvers).__name__}"
    for resolver in resolvers:
        assert "IpamPrefixListResolverId" in resolver, f"resolver missing id field: {sorted(resolver)}"
        assert "State" in resolver, f"resolver missing State field: {sorted(resolver)}"
    # With no MaxResults given, the service returns the full result set in one
    # page: NextToken must be absent/null, not a truncation cursor.
    assert resp.get("NextToken") is None, f"unexpected pagination cursor: {resp.get('NextToken')!r}"

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
