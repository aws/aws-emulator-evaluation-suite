"""op-contract-purchase-host-reservation-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-purchase-host-reservation-rejected"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PurchaseHostReservation with a real catalog offering fails with InvalidHostId.NotFound for a
    well-formed unknown host id and with InvalidHostID.Malformed for a malformed one, each with its
    exact message: existence is checked before the offering, shape before existence."""
    ec2 = ctx.client("ec2")

    offerings = ec2.describe_host_reservation_offerings().get("OfferingSet", [])
    assert offerings, "expected a non-empty catalog of host reservation offerings"
    real_offering_id = offerings[0]["OfferingId"]

    err, err_message = _client_error(
        lambda: ec2.purchase_host_reservation(
            OfferingId=real_offering_id, HostIdSet=["h-00000000000000000"]
        )
    )
    assert err == "InvalidHostId.NotFound", (
        f"a well-formed but nonexistent host ID against a REAL offering: expected "
        f"InvalidHostId.NotFound, got {err!r}"
    )
    expected_message = "The specified Dedicated host IDs ['h-00000000000000000'] are not valid."
    assert err_message == expected_message, f"expected message {expected_message!r}, got {err_message!r}"

    err_malformed, err_malformed_message = _client_error(
        lambda: ec2.purchase_host_reservation(
            OfferingId=real_offering_id, HostIdSet=["not-a-host-id"]
        )
    )
    # Note the casing: AWS spells this code "InvalidHostID" (capital ID), not
    # "InvalidHostId" like the NotFound code above.
    assert err_malformed == "InvalidHostID.Malformed", (
        f"a host ID of the wrong shape: expected InvalidHostID.Malformed, got "
        f"{err_malformed!r}"
    )
    expected_message = "The dedicated-host ID 'not-a-host-id' is malformed"
    assert err_malformed_message == expected_message, f"expected message {expected_message!r}, got {err_malformed_message!r}"


def _client_error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
