"""reserved-node-offering-not-found-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "reserved-node-offering-not-found-rejected"
GROUP = "error-semantics"
SERVICES = ["redshift"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PurchaseReservedNodeOffering for a nonexistent offering id fails with ReservedNodeOfferingNotFound
    "ReservedNodeOfferingId <id> not found." and no reserved node carries that id."""
    redshift = ctx.client("redshift")
    bogus_offering_id = "00000000-0000-0000-0000-000000000000"

    # Positive control: the catalog read itself works, so the rejection below is
    # specific to the bogus id / purchase eligibility, not a blanket failure of
    # the client or credentials.
    offerings_resp = redshift.describe_reserved_node_offerings(MaxRecords=20)
    assert "ReservedNodeOfferings" in offerings_resp

    code, message = _error(
        lambda: redshift.purchase_reserved_node_offering(
            ReservedNodeOfferingId=bogus_offering_id
        )
    )
    assert code == "ReservedNodeOfferingNotFound", f"expected ReservedNodeOfferingNotFound, got {code}"
    expected_message = f"ReservedNodeOfferingId {bogus_offering_id} not found."
    assert message == expected_message, (
        f"expected message {expected_message!r}, got {message!r}"
    )

    # Effect-absent, via an independent read: no reserved node was purchased
    # under the bogus offering id.
    nodes = redshift.describe_reserved_nodes().get("ReservedNodes", [])
    assert not any(n.get("ReservedNodeOfferingId") == bogus_offering_id for n in nodes), (
        "a reserved node was created despite the offering lookup failing"
    )


def _error(fn):
    """Call fn(); return (code, message) of the ClientError it raises. An unexpected SUCCESS
    raises, so a target that accepts a call real AWS refuses never reads as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
