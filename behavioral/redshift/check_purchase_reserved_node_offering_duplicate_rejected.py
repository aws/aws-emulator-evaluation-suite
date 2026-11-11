"""purchase-reserved-node-offering-duplicate-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "purchase-reserved-node-offering-duplicate-rejected"
GROUP = "overly-permissive"
SERVICES = ["redshift"]


@tags("axis:rejection", "cap:c1", "cap:c5", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PurchaseReservedNodeOffering with a nonexistent offering id is rejected with
    ReservedNodeOfferingNotFound "ReservedNodeOfferingId <id> not found." and creates no reserved
    node, while DescribeReservedNodeOfferings resolves a real offering by its id."""
    import uuid

    redshift = ctx.client("redshift")
    # ReservedNodeOfferingId must be a syntactically valid UUID for the service to look it up
    # (and reject it as not-found) rather than reject the shape of the identifier itself.
    bogus_offering_id = str(uuid.uuid4())

    code, message = _error(
        lambda: redshift.purchase_reserved_node_offering(
            ReservedNodeOfferingId=bogus_offering_id, NodeCount=1
        )
    )
    assert code == "ReservedNodeOfferingNotFound", f"expected ReservedNodeOfferingNotFound, got {code!r}"
    assert message == f"ReservedNodeOfferingId {bogus_offering_id} not found.", (
        f"unexpected ReservedNodeOfferingNotFound message {message!r}"
    )

    # effect absent: the rejected attempt did not create a ReservedNode under that offering id.
    reserved_nodes = redshift.describe_reserved_nodes()["ReservedNodes"]
    assert bogus_offering_id not in {node.get("ReservedNodeOfferingId") for node in reserved_nodes}, (
        f"a ReservedNode referencing the rejected offering id {bogus_offering_id} exists"
    )

    # positive control: a real, purchasable offering still resolves by id -- this is not a blanket
    # failure of PurchaseReservedNodeOffering's underlying offering lookup.
    offerings = redshift.describe_reserved_node_offerings()["ReservedNodeOfferings"]
    if not offerings:
        raise AssertionError(
            "no ReservedNodeOfferings exist in this account/region to use as a positive control"
        )
    real_offering_id = offerings[0]["ReservedNodeOfferingId"]
    control = redshift.describe_reserved_node_offerings(
        ReservedNodeOfferingId=real_offering_id
    )["ReservedNodeOfferings"]
    assert len(control) == 1, f"expected exactly 1 offering for {real_offering_id}, got {len(control)}"
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
