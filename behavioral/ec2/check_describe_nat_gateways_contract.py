"""describe-nat-gateways-contract."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "describe-nat-gateways-contract"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeNatGateways: success contract (list payload + DryRun), and an unrecognized
    filter name is accepted (not rejected)."""
    ec2 = ctx.client("ec2")

    resp = ec2.describe_nat_gateways(MaxResults=5)
    nat_gateways = resp["NatGateways"]
    _assert_page_contract(nat_gateways, resp.get("NextToken"), max_results=5)

    _assert_dry_run_ok(lambda: ec2.describe_nat_gateways(DryRun=True))

    # Unlike many Describe* calls, EC2 does not validate the filter Name here: an unrecognized
    # name is accepted (200, no ClientError).
    resp2 = ec2.describe_nat_gateways(Filters=[{"Name": "sim2real-bogus-filter", "Values": ["x"]}])
    assert isinstance(resp2["NatGateways"], list), (
        f"expected NatGateways to be a list, got {type(resp2['NatGateways'])!r}"
    )


_DRY_RUN_MESSAGE = "Request would have succeeded, but DryRun flag is set."


def _assert_page_contract(items, next_token, *, max_results):
    # NextToken is null once fewer than MaxResults items come back.
    assert isinstance(items, list), f"expected NatGateways to be a list, got {type(items)!r}"
    assert len(items) <= max_results, f"expected at most {max_results} items, got {len(items)}"
    if len(items) < max_results:
        assert not next_token, "NextToken must be empty when the returned page is not full"


def _assert_dry_run_ok(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        message = exc.response["Error"].get("Message", "")
        assert code == "DryRunOperation", f"expected DryRunOperation, got {code!r}"
        assert message == _DRY_RUN_MESSAGE, f"unexpected DryRunOperation message {message!r}"
        return
    raise AssertionError("expected DryRunOperation error, call unexpectedly succeeded")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
