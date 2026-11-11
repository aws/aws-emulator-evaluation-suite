"""calculate-isolines-too-many-thresholds-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "calculate-isolines-too-many-thresholds-rejected"
GROUP = "overly-permissive"
SERVICES = ["geo-routes"]

_SPACE_NEEDLE = [-122.3493, 47.6205]


@tags("axis:rejection", "cap:unclassified", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A single Thresholds type is capped at 5 values; 6 time thresholds are
    rejected with ValidationException while exactly 5 (positive control, the
    boundary) succeeds."""
    client = ctx.client("geo-routes")

    error = _client_error(
        lambda: client.calculate_isolines(
            Origin=_SPACE_NEEDLE,
            TravelMode="Pedestrian",
            Thresholds={"Time": [60, 120, 180, 240, 300, 360]},
        )
    )
    assert error["Code"] == "ValidationException", f"expected ValidationException, got {error!r}"
    assert error["Message"] == "'Thresholds.Time' must have length at most 5", (
        f"unexpected message: {error['Message']!r}"
    )

    resp = client.calculate_isolines(
        Origin=_SPACE_NEEDLE,
        TravelMode="Pedestrian",
        Thresholds={"Time": [60, 120, 180, 240, 300]},
    )
    assert len(resp["Isolines"]) == 5, (
        f"expected 5 isolines for the boundary (5) threshold count, "
        f"got {len(resp['Isolines'])}"
    )


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because an emulator
    ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(
        f"real AWS rejects 6 time thresholds, but the call SUCCEEDED and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
