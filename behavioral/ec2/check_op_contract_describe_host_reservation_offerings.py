"""op-contract-describeHostReservationOfferings."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-describeHostReservationOfferings"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c5", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeHostReservationOfferings scopes by duration/instance-family and rejects a
    nonexistent offering ID."""
    ec2 = ctx.client("ec2")

    one_year = 31536000
    three_year = 94608000

    # --- success path: the public catalog of offerings must honor the documented
    # instance-family filter and the Min/MaxDuration bounds (offerings are 1yr or 3yr only) ---
    resp = ec2.describe_host_reservation_offerings(
        Filter=[{"Name": "instance-family", "Values": ["m5"]}],
        MinDuration=one_year,
        MaxDuration=three_year,
    )
    assert "OfferingSet" in resp, f"expected OfferingSet in response, got keys {list(resp)!r}"
    assert isinstance(resp["OfferingSet"], list), (
        f"expected OfferingSet to be a list, got {type(resp['OfferingSet'])!r}"
    )
    assert len(resp["OfferingSet"]) > 0, (
        "expected at least one m5 offering in the 1yr-3yr window, got an empty OfferingSet"
    )
    for offering in resp["OfferingSet"]:
        assert offering["InstanceFamily"] == "m5", (
            f"filtered on instance-family=m5 but got {offering['InstanceFamily']!r}"
        )
        assert offering["Duration"] in (one_year, three_year), (
            f"expected Duration in {{{one_year}, {three_year}}}, got {offering['Duration']!r}"
        )

    # --- error boundary: a well-formed but nonexistent offering ID must be rejected --
    # (MinDuration/MaxDuration are documented as *bounds*, not exact-match values, so an
    # off-grid duration like 12345 is valid input and is not rejected)
    bogus_offering_id = "hro-0123456789abcdef0"

    def _call():
        ec2.describe_host_reservation_offerings(OfferingId=bogus_offering_id)

    code, message = _error(_call)
    assert code == "InvalidHostReservationOfferingId.Malformed", (
        f"expected InvalidHostReservationOfferingId.Malformed, got {code!r}"
    )
    expected = f"The specified host reservation Offering ID '{bogus_offering_id}' is not valid."
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _error(fn):
    """Return fn()'s (code, message); a success raises, never reading as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err["Message"]
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
