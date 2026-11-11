"""describe-network-interface-permissions-contract."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "describe-network-interface-permissions-contract"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeNetworkInterfacePermissions: success contract (list payload) and MaxResults
    below the documented minimum (5) rejection."""
    ec2 = ctx.client("ec2")

    resp = ec2.describe_network_interface_permissions(MaxResults=5)
    assert resp["ResponseMetadata"]["HTTPStatusCode"] == 200
    permissions = resp["NetworkInterfacePermissions"]
    _assert_page_contract(permissions, resp.get("NextToken"), max_results=5)

    # MaxResults must be 5-255. Client-side validation is bypassed so the request reaches the
    # service, which answers with its own InvalidMaxResults.
    from botocore.config import Config
    from botocore.exceptions import ClientError

    ec2_raw = ctx.client("ec2", config=Config(parameter_validation=False))
    try:
        ec2_raw.describe_network_interface_permissions(MaxResults=1)
        raise AssertionError("expected InvalidMaxResults rejection, call unexpectedly succeeded")
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        msg = exc.response["Error"]["Message"]
        assert code == "InvalidMaxResults", f"expected InvalidMaxResults, got {code!r}: {msg}"
        expected = "Value ( 1 ) for parameter maxResults is invalid. Expecting a value greater than or equal to 5."
        assert msg == expected, f"expected message {expected!r}, got {msg!r}"


def _assert_page_contract(items, next_token, *, max_results):
    # A page never exceeds MaxResults. Unlike many Describe* calls, a NextToken may come back even
    # on a non-full page, since pagination runs before account-visibility filtering.
    assert isinstance(items, list)
    assert len(items) <= max_results, f"expected at most {max_results} items, got {len(items)}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
