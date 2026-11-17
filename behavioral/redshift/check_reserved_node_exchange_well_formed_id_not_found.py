"""reserved-node-exchange-well-formed-id-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "reserved-node-exchange-well-formed-id-not-found"
GROUP = "reserved-nodes"
SERVICES = ["redshift"]

_WELL_FORMED_ID = "11111111-1111-1111-1111-111111111111"


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A well-formed but unowned reserved-node id reports ReservedNodeNotFound, and a well-formed
    but unowned exchange-request id reports the exchange-status not-found, each with its own
    message, while the reserved-node catalog itself still answers."""
    rs = ctx.client("redshift")

    catalog = rs.describe_reserved_node_offerings(MaxRecords=20)["ReservedNodeOfferings"]
    assert isinstance(catalog, list), f"reserved-node catalog read must succeed, got {catalog!r}"

    code, message = _error(
        lambda: rs.get_reserved_node_exchange_offerings(ReservedNodeId=_WELL_FORMED_ID)
    )
    assert code == "ReservedNodeNotFound", f"expected ReservedNodeNotFound, got {code}: {message!r}"
    expected = f"Reserved Node {_WELL_FORMED_ID} not found."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    code, message = _error(
        lambda: rs.accept_reserved_node_exchange(
            ReservedNodeId=_WELL_FORMED_ID, TargetReservedNodeOfferingId=_WELL_FORMED_ID
        )
    )
    assert code == "ReservedNodeNotFound", f"expected ReservedNodeNotFound, got {code}: {message!r}"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    code, message = _error(
        lambda: rs.describe_reserved_node_exchange_status(ReservedNodeId=_WELL_FORMED_ID)
    )
    assert code == "ReservedNodeNotFound", f"expected ReservedNodeNotFound, got {code}: {message!r}"
    expected_status = f"ReservedNodeId {_WELL_FORMED_ID} not found."
    assert message == expected_status, f"expected message {expected_status!r}, got {message!r}"

    code, message = _error(
        lambda: rs.describe_reserved_node_exchange_status(
            ReservedNodeExchangeRequestId=_WELL_FORMED_ID
        )
    )
    assert code == "ReservedNodeExchangeNotFond", f"expected ReservedNodeExchangeNotFond, got {code}: {message!r}"
    expected_request = "The reserved-node exchange status was not found."
    assert message == expected_request, f"expected message {expected_request!r}, got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
