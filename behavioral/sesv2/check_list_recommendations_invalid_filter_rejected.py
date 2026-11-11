"""list-recommendations-invalid-filter-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-recommendations-invalid-filter-rejected"
GROUP = "error-semantics"
SERVICES = ["sesv2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListRecommendations accepts a lone STATUS filter and a valid TYPE with IMPACT, and refuses a TYPE outside
    RecommendationType with BadRequestException and the exact message "Invalid recommendation TYPE
    specified".
    """
    ses = ctx.client("sesv2")

    # positive control: an individually valid filter key is accepted (may return zero items).
    result = ses.list_recommendations(Filter={"STATUS": "OPEN"})
    assert "Recommendations" in result, (
        f"a lone STATUS filter must be accepted; response was {result!r}"
    )

    combined = ses.list_recommendations(Filter={"TYPE": "DKIM", "IMPACT": "HIGH"})
    assert "Recommendations" in combined, (
        f"a valid TYPE combined with IMPACT must be accepted; response was {combined!r}"
    )

    # VDM_AUTOMATIC_DATA_PROTECTION is not a RecommendationType value.
    err = _error(
        lambda: ses.list_recommendations(
            Filter={"TYPE": "VDM_AUTOMATIC_DATA_PROTECTION", "IMPACT": "HIGH"}
        )
    )
    assert err.get("Code") == "BadRequestException", (
        f"an unknown TYPE filter value must be rejected with BadRequestException, got {err!r}"
    )
    expected = "Invalid recommendation TYPE specified"
    assert err.get("Message") == expected, f"expected message {expected!r}, got {err.get('Message')!r}"


def _error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because an emulator
    ACCEPTING a filter value real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as err:
        return err.response.get("Error", {})
    raise AssertionError(
        f"real AWS rejects this filter, but it SUCCEEDED and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
