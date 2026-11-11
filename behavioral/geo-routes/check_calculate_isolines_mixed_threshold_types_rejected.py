"""calculate-isolines-mixed-threshold-types-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "calculate-isolines-mixed-threshold-types-rejected"
GROUP = "overly-permissive"
SERVICES = ["geo-routes"]

ORIGIN = [-122.3410, 47.6089]


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because an emulator
    ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as err:
        return err.response.get("Error", {})
    raise AssertionError(
        f"real AWS rejects mixed Distance/Time thresholds, but the call SUCCEEDED and "
        f"returned {result!r}"
    )


@tags("axis:rejection", "cap:unclassified", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """IsolineThresholds documents that all thresholds in a single request must
    be the same type: mixing Distance and Time thresholds together must be
    rejected with ValidationException, while a same-typed request succeeds."""
    client = ctx.client("geo-routes")

    error = _client_error(
        lambda: client.calculate_isolines(
            Origin=ORIGIN, Thresholds={"Distance": [2000], "Time": [600]}
        )
    )
    assert error.get("Code") == "ValidationException", (
        f"expected ValidationException for mixed Distance/Time thresholds, got {error!r}"
    )
    assert error["Message"] == (
        "Only one of the following fields may be set within 'Thresholds': "
        "'Consumption', 'Distance', 'Time'."
    ), (
        f"unexpected message: {error['Message']!r}"
    )

    # Positive control: a single-typed Thresholds request on the same Origin
    # succeeds -- the operation itself, not just error paths, still works.
    resp = client.calculate_isolines(Origin=ORIGIN, Thresholds={"Time": [600]})
    assert len(resp["Isolines"]) == 1, (
        f"expected exactly 1 isoline for a single Time threshold, got {resp['Isolines']!r}"
    )
    assert resp["Isolines"][0]["TimeThreshold"] == 600, (
        f"expected TimeThreshold 600, got {resp['Isolines'][0].get('TimeThreshold')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
