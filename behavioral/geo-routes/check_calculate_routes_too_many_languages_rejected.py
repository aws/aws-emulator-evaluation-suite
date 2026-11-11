"""calculate-routes-too-many-languages-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "calculate-routes-too-many-languages-rejected"
GROUP = "overly-permissive"
SERVICES = ["geo-routes"]

_SEATTLE = [-122.3321, 47.6062]
_PORTLAND = [-122.6784, 45.5152]
_TEN_LANGUAGES = ["en", "fr", "de", "es", "it", "pt", "nl", "sv", "da", "fi"]
_ELEVEN_LANGUAGES = _TEN_LANGUAGES + ["no"]


@tags("axis:rejection", "cap:c5", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Languages is capped at 10 entries; an 11th is rejected with
    ValidationException while exactly 10 (positive control, the boundary) is
    accepted."""
    client = ctx.client("geo-routes")

    error = _client_error(
        lambda: client.calculate_routes(
            Origin=_SEATTLE,
            Destination=_PORTLAND,
            TravelMode="Car",
            Languages=_ELEVEN_LANGUAGES,
        )
    )
    assert error["Code"] == "ValidationException", (
        f"expected ValidationException for {len(_ELEVEN_LANGUAGES)} languages, "
        f"got {error['Code']!r}"
    )
    assert error["Message"] == "'Languages' must have length at most 10", (
        f"unexpected message: {error['Message']!r}"
    )

    resp = client.calculate_routes(
        Origin=_SEATTLE,
        Destination=_PORTLAND,
        TravelMode="Car",
        Languages=_TEN_LANGUAGES,
    )
    assert len(resp["Routes"]) >= 1, (
        f"the boundary value of {len(_TEN_LANGUAGES)} languages (positive control) "
        f"was rejected or returned no routes: {resp!r}"
    )


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because an emulator
    ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(
        f"real AWS rejects 11 languages, but the call SUCCEEDED and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
