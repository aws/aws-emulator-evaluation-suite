"""calculate-isolines-missing-origin-and-destination-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "calculate-isolines-missing-origin-and-destination-rejected"
GROUP = "overly-permissive"
SERVICES = ["geo-routes"]

_ORIGIN = [-122.3421, 47.6097]  # Pike Place Market, Seattle


def _client_error(fn):
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(
        f"expected ValidationException but the call succeeded: {result!r}"
    )


@tags("axis:rejection", "cap:unclassified", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """CalculateIsolines with neither Origin nor Destination is rejected with ValidationException and its
    exact message, while the same request with an Origin returns one isoline.
    """
    client = ctx.client("geo-routes")

    error = _client_error(
        lambda: client.calculate_isolines(Thresholds={"Time": [600]}, TravelMode="Car")
    )
    assert error["Code"] == "ValidationException", f"expected ValidationException, got {error!r}"
    assert error["Message"] == (
        "At least one of the following fields must be set: 'Origin', 'Destination'."
    ), (
        f"unexpected message: {error['Message']!r}"
    )

    # Positive control: the identical request with Origin supplied succeeds.
    resp = client.calculate_isolines(
        Origin=_ORIGIN, Thresholds={"Time": [600]}, TravelMode="Car"
    )
    assert len(resp["Isolines"]) == 1, f"expected 1 isoline, got {len(resp['Isolines'])}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
