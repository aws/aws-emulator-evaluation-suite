"""calculate-routes-max-alternatives-out-of-range-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "calculate-routes-max-alternatives-out-of-range-rejected"
GROUP = "overly-permissive"
SERVICES = ["geo-routes"]

_SEATTLE = [-122.3321, 47.6062]
_PORTLAND = [-122.6784, 45.5152]


@tags("axis:rejection", "cap:unclassified", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """MaxAlternatives is bounded to [0,5]; 6 is rejected with ValidationException
    while the boundary value 5 (positive control) is accepted."""
    client = ctx.client("geo-routes")

    error = _client_error(
        lambda: client.calculate_routes(
            Origin=_SEATTLE, Destination=_PORTLAND, TravelMode="Car", MaxAlternatives=6
        )
    )
    assert error["Code"] == "ValidationException", (
        f"expected ValidationException for MaxAlternatives=6, got {error!r}"
    )
    assert error["Message"] == "'MaxAlternatives' must not be greater than 5", (
        f"unexpected message: {error['Message']!r}"
    )

    resp = client.calculate_routes(
        Origin=_SEATTLE, Destination=_PORTLAND, TravelMode="Car", MaxAlternatives=5
    )
    routes = resp["Routes"]
    assert 1 <= len(routes) <= 6, (
        f"expected between 1 and 6 routes for MaxAlternatives=5, got {len(routes)}"
    )


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(
        f"expected MaxAlternatives=6 to be rejected, but the call SUCCEEDED and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
