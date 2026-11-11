"""reverse-geocode-radius-out-of-range-rejected."""
from __future__ import annotations

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "reverse-geocode-radius-out-of-range-rejected"
GROUP = "overly-permissive"
SERVICES = ["geo-places"]


def _error_code(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c5", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """ReverseGeocode with QueryRadius 0, sent past client-side validation, is rejected by the service with
    ValidationException and its exact message, while an in-range radius returns results.
    """
    geo = ctx.client("geo-places")
    position = [-122.3493, 47.6205]

    # Positive control: an in-range radius succeeds.
    control = geo.reverse_geocode(QueryPosition=position, QueryRadius=1000)
    assert control.get("ResultItems"), "control ReverseGeocode call unexpectedly returned no results"

    raw = ctx.client("geo-places", config=Config(parameter_validation=False))
    code, message = _error_code(lambda: raw.reverse_geocode(QueryPosition=position, QueryRadius=0))
    assert code == "ValidationException", f"expected ValidationException for QueryRadius=0, got {code}"
    expected_message = "'QueryRadius' must not be less than 1"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
