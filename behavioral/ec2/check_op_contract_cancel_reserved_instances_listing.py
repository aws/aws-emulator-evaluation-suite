"""op-contract-cancel-reserved-instances-listing."""
from __future__ import annotations

from typing import Any, Callable

from behavioral_harness import tags

CHECK = "op-contract-cancel-reserved-instances-listing"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CancelReservedInstancesListing rejects both a well-formed nonexistent listing ID and a malformed
    one with InvalidInput and its exact message, while DescribeRegions with the same credentials
    succeeds."""
    ec2 = ctx.client("ec2")

    regions = ec2.describe_regions(RegionNames=[ctx.region])["Regions"]
    assert any(r["RegionName"] == ctx.region for r in regions), (
        f"positive control failed: describe_regions did not return {ctx.region}, got {regions}"
    )

    code, code_message = _error_code(
        lambda: ec2.cancel_reserved_instances_listing(
            ReservedInstancesListingId="00000000-0000-0000-0000-000000000000"
        )
    )
    assert code == "InvalidInput", f"expected InvalidInput, got {code}"
    expected_code_message = " Invalid value for 'listingId'"
    assert code_message == expected_code_message, f"expected message {expected_code_message!r}, got {code_message!r}"

    code2, code2_message = _error_code(
        lambda: ec2.cancel_reserved_instances_listing(
            ReservedInstancesListingId="totally-not-a-listing-id"
        )
    )
    assert code2 == "InvalidInput", f"expected InvalidInput, got {code2}"
    expected_code2_message = (
        "1 validation error detected: Value 'totally-not-a-listing-id' at 'reservedInstanceListingId' "
        "failed to satisfy constraint: Member must satisfy regular expression pattern: "
        r"\w{8}(-\w{4}){3}-\w{12}"
    )
    assert code2_message == expected_code2_message, f"expected message {expected_code2_message!r}, got {code2_message!r}"


def _error_code(fn: Callable[[], Any]) -> tuple[str, str | None]:
    """Call fn() and return its (code, message); a call that succeeds raises."""
    try:
        result = fn()
    except Exception as exc:
        err = getattr(exc, "response", {}).get("Error")
        if not err:
            raise
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
