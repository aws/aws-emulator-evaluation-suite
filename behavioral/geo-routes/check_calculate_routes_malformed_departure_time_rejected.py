"""calculate-routes-malformed-departure-time-rejected."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "calculate-routes-malformed-departure-time-rejected"
GROUP = "overly-permissive"
SERVICES = ["geo-routes"]

ORIGIN = [-122.3410, 47.6089]
DESTINATION = [-122.3088, 47.4502]


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:unclassified", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A DepartureTime that does not parse as an ISO-8601 timestamp must be
    rejected server-side with ValidationException, while a well-formed,
    near-future timestamp for the same request succeeds."""
    client = ctx.client("geo-routes")

    error = _client_error(
        lambda: client.calculate_routes(
            Origin=ORIGIN, Destination=DESTINATION, DepartureTime="not-a-timestamp"
        )
    )
    assert error["Code"] == "ValidationException", f"expected ValidationException, got {error!r}"
    assert error["Message"] == (
        "'DepartureTime' must match regex "
        r"^([1-2][0-9]{3})-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])T([01][0-9]|2[0-3]):"
        r"([0-5][0-9]):([0-5][0-9]|60)(\.[0-9]{0,9})?(Z|[+-]([01][0-9]|2[0-3]):[0-5][0-9])$"
    ), (
        f"unexpected message: {error['Message']!r}"
    )

    # Positive control: same request shape, a valid ISO-8601 departure time.
    valid_time = (datetime.now(timezone.utc) + timedelta(hours=1)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    resp = client.calculate_routes(
        Origin=ORIGIN, Destination=DESTINATION, DepartureTime=valid_time
    )
    routes = resp["Routes"]
    assert len(routes) >= 1, f"expected >=1 route for valid DepartureTime, got {len(routes)}"
    distance = routes[0]["Summary"]["Distance"]
    assert distance > 0, f"expected positive route distance, got {distance}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
