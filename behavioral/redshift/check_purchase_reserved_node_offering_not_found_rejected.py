"""purchase-reserved-node-offering-not-found-rejected."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "purchase-reserved-node-offering-not-found-rejected"
GROUP = "overly-permissive"
SERVICES = ["redshift"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PurchaseReservedNodeOffering for a nonexistent offering id is rejected with
    ReservedNodeOfferingNotFound and its exact message, purchases nothing, and a real offering id
    from the catalog still resolves."""
    redshift = ctx.client("redshift")

    offerings = redshift.describe_reserved_node_offerings(MaxRecords=20).get(
        "ReservedNodeOfferings", []
    )
    if not offerings:
        raise AssertionError(
            "no ReservedNodeOfferings exist in this account/region to use as a "
            "positive control"
        )
    real_offering_id = offerings[0]["ReservedNodeOfferingId"]

    bogus_offering_id = str(uuid.uuid4())

    code, message = _error(
        lambda: redshift.purchase_reserved_node_offering(ReservedNodeOfferingId=bogus_offering_id)
    )
    assert code == "ReservedNodeOfferingNotFound", (
        f"expected ReservedNodeOfferingNotFound, got {code}"
    )
    assert message == f"ReservedNodeOfferingId {bogus_offering_id} not found.", (
        f"unexpected ReservedNodeOfferingNotFound message {message!r}"
    )

    # Effect absent: no reserved node was purchased under the bogus offering id.
    nodes = redshift.describe_reserved_nodes().get("ReservedNodes", [])
    assert not any(n.get("ReservedNodeOfferingId") == bogus_offering_id for n in nodes), (
        "a reserved node was created despite the offering lookup failing"
    )

    # Positive control: a real offering id from the account's own catalog still
    # resolves through the same lookup path that just rejected the bogus id.
    control = redshift.describe_reserved_node_offerings(
        ReservedNodeOfferingId=real_offering_id
    )["ReservedNodeOfferings"]
    assert len(control) == 1, f"expected exactly 1 offering for {real_offering_id}, got {control!r}"
    assert control[0]["ReservedNodeOfferingId"] == real_offering_id, (
        f"expected {real_offering_id}, got {control[0].get('ReservedNodeOfferingId')!r}"
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
