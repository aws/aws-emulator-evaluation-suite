"""op-contract-describeHostReservations."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-describeHostReservations"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeHostReservations returns the well-formed collection shape and rejects an
    unrecognized host reservation ID as malformed (real AWS classifies this ID shape as
    InvalidHostReservationId.Malformed, not a not-found)."""
    ec2 = ctx.client("ec2")

    # --- success path: the account-wide collection is well-formed (its content is account state) ---
    resp = ec2.describe_host_reservations()
    assert "HostReservationSet" in resp, f"response missing HostReservationSet: {resp!r}"
    assert isinstance(resp["HostReservationSet"], list), (
        f"HostReservationSet must be a list, got {type(resp['HostReservationSet'])!r}"
    )

    # A syntactically valid filter is accepted and every returned record honours it.
    filtered = ec2.describe_host_reservations(Filter=[{"Name": "state", "Values": ["active"]}])
    assert isinstance(filtered["HostReservationSet"], list), (
        f"filtered HostReservationSet must be a list, got {filtered['HostReservationSet']!r}"
    )
    for item in filtered["HostReservationSet"]:
        assert item.get("State") == "active", f"filter state=active returned {item!r}"

    # --- error boundary: an unrecognized host reservation ID must be rejected. (This API does
    # not validate unrecognized filter names -- it silently ignores them -- so we probe with a
    # bogus resource ID instead. AWS classifies this ID shape as Malformed, not NotFound
    # -- see the exact code asserted below.) ---
    bogus_id = "hr-0123456789abcdef0"

    def _call():
        ec2.describe_host_reservations(HostReservationIdSet=[bogus_id])

    code, message = _error(_call)
    assert code == "InvalidHostReservationId.Malformed", (
        f"expected InvalidHostReservationId.Malformed for a bogus host reservation ID, got {code!r}"
    )
    assert message == f"The specified host Reservation IDs ['{bogus_id}'] are not valid.", (
        f"unexpected Malformed message: {message!r}"
    )


def _error(fn):
    """Call fn(); return (code, message) of its botocore error. An unexpected SUCCESS raises, because
    an emulator accepting an ID real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(
        f"real AWS rejects a nonexistent host reservation ID, but the call SUCCEEDED and "
        f"returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
