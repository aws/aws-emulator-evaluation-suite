"""disable-region-enabled-by-default-conflict-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "disable-region-enabled-by-default-conflict-rejected"
GROUP = "overly-permissive"
SERVICES = ["account"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DisableRegion on us-east-1, which is enabled by default and cannot be opted out, is rejected
    with ValidationException, its opt status stays ENABLED_BY_DEFAULT, and GetRegionOptStatus on an
    opt-in Region still answers."""
    account = ctx.client("account")

    # us-east-1 is region-pinned by construction: it is the one Region every commercial account
    # has ENABLED_BY_DEFAULT and can never opt out of, which is the exact subject under test.
    before = account.get_region_opt_status(RegionName="us-east-1")["RegionOptStatus"]
    assert before == "ENABLED_BY_DEFAULT", before

    code, message = _error_code(lambda: account.disable_region(RegionName="us-east-1"))
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    assert message == "us-east-1 is not a valid region for opt-in or opt-out.", message

    # the effect must be absent: status is unchanged
    after = account.get_region_opt_status(RegionName="us-east-1")["RegionOptStatus"]
    assert after == "ENABLED_BY_DEFAULT", f"expected ENABLED_BY_DEFAULT, got {after!r}"

    # positive control: the read path for the same API surface still works for an opt-in region.
    # af-south-1 is pinned because it is an ordinary opt-in Region (never ENABLED_BY_DEFAULT), so
    # this also catches a target that fails to distinguish per-region opt status.
    control = account.get_region_opt_status(RegionName="af-south-1")["RegionOptStatus"]
    assert control in {"ENABLED", "ENABLING", "DISABLING", "DISABLED"}, (
        f"expected an opt-in status for af-south-1, got {control!r}"
    )


def _error_code(fn):
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
