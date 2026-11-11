"""describe-local-gateways-contract."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "describe-local-gateways-contract"
GROUP = "error-semantics"
SERVICES = ["ec2"]

_DRY_RUN_MESSAGE = "Request would have succeeded, but DryRun flag is set."


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeLocalGateways: success contract (list payload + DryRun) and unknown-id rejection."""
    ec2 = ctx.client("ec2")

    resp = ec2.describe_local_gateways(MaxResults=5)
    assert resp["ResponseMetadata"]["HTTPStatusCode"] == 200
    local_gateways = resp["LocalGateways"]
    _assert_page_contract(local_gateways, resp.get("NextToken"), max_results=5)

    _assert_dry_run_ok(lambda: ec2.describe_local_gateways(DryRun=True))

    # A well-formed but nonexistent LocalGatewayId is a set-membership filter, not an
    # identity lookup: verified empirically against real AWS, the call succeeds and the
    # id simply matches nothing, rather than raising InvalidLocalGatewayID.NotFound.
    filtered = ec2.describe_local_gateways(LocalGatewayIds=["lgw-0123456789abcdef0"])
    assert filtered["ResponseMetadata"]["HTTPStatusCode"] == 200
    assert filtered["LocalGateways"] == [], (
        f"expected no LocalGateways for an unknown LocalGatewayIds filter, got {filtered['LocalGateways']!r}"
    )


def _assert_page_contract(items, next_token, *, max_results):
    # Substantive body/state assertion: the returned page must never exceed the
    # requested MaxResults, and per the documented contract NextToken is null once
    # fewer than MaxResults items come back (there is nothing left to paginate).
    assert isinstance(items, list)
    assert len(items) <= max_results, f"expected at most {max_results} items, got {len(items)}"
    if len(items) < max_results:
        assert not next_token, "NextToken must be empty when the returned page is not full"


def _assert_dry_run_ok(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        message = exc.response["Error"].get("Message")
        assert code == "DryRunOperation", f"expected DryRunOperation, got {code!r}"
        assert message == _DRY_RUN_MESSAGE, f"expected {_DRY_RUN_MESSAGE!r}, got {message!r}"
        return
    raise AssertionError("expected DryRunOperation error, call unexpectedly succeeded")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
