"""purchase-reserved-node-offering-invalid-id-rejected."""
from __future__ import annotations

import uuid

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "purchase-reserved-node-offering-invalid-id-rejected"
GROUP = "overly-permissive"
SERVICES = ["redshift"]


@tags("axis:rejection", "cap:c1", "cap:c5", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PurchaseReservedNodeOffering with a fabricated offering id is rejected with
    ReservedNodeOfferingNotFound and its exact message and creates no reservation, while a real
    offering id still resolves through DescribeReservedNodeOfferings."""
    redshift = ctx.client("redshift")

    offerings = redshift.describe_reserved_node_offerings()["ReservedNodeOfferings"]
    if not offerings:
        raise AssertionError(
            "no ReservedNodeOfferings exist in this account/region to use as a "
            "positive control"
        )
    real_offering_id = offerings[0]["ReservedNodeOfferingId"]

    bogus_id = str(uuid.uuid4())
    code, message = _error(
        lambda: redshift.purchase_reserved_node_offering(ReservedNodeOfferingId=bogus_id)
    )
    assert code == "ReservedNodeOfferingNotFound", f"CODE={code!r}"
    assert message == f"ReservedNodeOfferingId {bogus_id} not found.", (
        f"unexpected ReservedNodeOfferingNotFound message {message!r}"
    )

    reserved = redshift.describe_reserved_nodes().get("ReservedNodes", [])
    assert all(r["ReservedNodeOfferingId"] != bogus_id for r in reserved), (
        "a reservation referencing the fabricated offering id was created"
    )

    control = redshift.describe_reserved_node_offerings(
        ReservedNodeOfferingId=real_offering_id
    )["ReservedNodeOfferings"]
    assert len(control) == 1, (
        f"expected exactly 1 offering for {real_offering_id!r}, got {len(control)}"
    )
    assert control[0]["ReservedNodeOfferingId"] == real_offering_id, (
        f"expected {real_offering_id!r}, got {control[0]['ReservedNodeOfferingId']!r}"
    )


def _error(fn):
    """Call fn(); return botocore (Error.Code, Error.Message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
