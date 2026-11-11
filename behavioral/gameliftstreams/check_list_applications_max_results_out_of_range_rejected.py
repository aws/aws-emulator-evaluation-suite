"""list-applications-max-results-out-of-range-rejected."""
from __future__ import annotations

from botocore.client import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-applications-max-results-out-of-range-rejected"
GROUP = "validation"
SERVICES = ["gameliftstreams"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListApplications with MaxResults 0, sent past client-side validation, is rejected by the service with
    ValidationException and its exact message, while a valid MaxResults returns Items.
    """
    gls = ctx.client("gameliftstreams")
    raw = ctx.client("gameliftstreams", config=Config(parameter_validation=False))

    code, message = _error_code(lambda: raw.list_applications(MaxResults=0))
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    expected = (
        "1 validation error detected: Value '0' at 'maxResults' failed to satisfy constraint: "
        "Member must have value greater than or equal to 1"
    )
    assert message == expected, f"expected {expected!r}, got {message!r}"

    # positive control: an in-range MaxResults value is accepted
    resp = gls.list_applications(MaxResults=1)
    assert "Items" in resp, f"expected an 'Items' key in ListApplications response, got {resp!r}"


def _error_code(fn):
    """Call fn(); return its botocore error code. An unexpected SUCCESS raises, because an
    over-permissive target accepting input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(
        f"real AWS rejects MaxResults=0 with ValidationException, but it SUCCEEDED and "
        f"returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
