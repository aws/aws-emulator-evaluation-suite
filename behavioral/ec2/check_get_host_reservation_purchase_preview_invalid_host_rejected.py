"""get-host-reservation-purchase-preview-invalid-host-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-host-reservation-purchase-preview-invalid-host-rejected"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetHostReservationPurchasePreview rejects a made-up Dedicated Host id of this
    shape with InvalidHostId.Malformed - AWS's own host-id format validation runs
    before any existence lookup."""
    ec2 = ctx.client("ec2")

    # Error boundary: a made-up host id of this shape fails AWS's own host-id
    # format validation and is rejected as Malformed before any existence check.
    bogus_host_id = "h-0123456789abcdef0"
    code, message = _error(
        lambda: ec2.get_host_reservation_purchase_preview(
            OfferingId="hro-0123456789abcdef0",
            HostIdSet=[bogus_host_id],
        )
    )
    assert code == "InvalidHostId.Malformed", f"expected InvalidHostId.Malformed, got {code!r}"
    expected = f"The specified Dedicated host IDs ['{bogus_host_id}'] are not valid."
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _error(fn):
    """Call fn(); return its error as (code, message). An unexpected SUCCESS raises rather than
    returning a falsy sentinel."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
