"""list-recommendations-unknown-resource-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-recommendations-unknown-resource-not-found"
GROUP = "error-semantics"
SERVICES = ["sesv2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListRecommendations validates RESOURCE_ARN shape, not existence: a non-ARN fails
    BadRequestException, while a well-formed ARN of a missing or a real identity is accepted."""
    ses = ctx.client("sesv2")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    malformed = _error(
        lambda: ses.list_recommendations(Filter={"RESOURCE_ARN": "not-an-arn-at-all"})
    )
    assert malformed == ("BadRequestException", "Filter resource is invalid"), (
        f"expected BadRequestException for a syntactically invalid RESOURCE_ARN, got {malformed!r}"
    )

    # A well-formed ARN for a missing resource is not rejected with NotFoundException.
    unknown_arn = (
        f"arn:aws:ses:{ctx.region}:{account_id}:identity/"
        f"{ctx.unique_name('sim2real-missing-')}.example.com"
    )
    unknown_result = ses.list_recommendations(Filter={"RESOURCE_ARN": unknown_arn})
    unknown_recs = unknown_result.get("Recommendations", [])
    assert unknown_recs == [], (
        f"expected an empty Recommendations list for a well-formed but nonexistent "
        f"RESOURCE_ARN (existence is not validated), got {unknown_recs!r}"
    )

    # A real identity may also have zero recommendations; only acceptance is asserted.
    domain = f"{ctx.unique_name('sim2real-idy-')}.example.com"
    ses.create_email_identity(EmailIdentity=domain)
    ctx.on_cleanup(lambda: ses.delete_email_identity(EmailIdentity=domain))
    real_arn = f"arn:aws:ses:{ctx.region}:{account_id}:identity/{domain}"

    result = ses.list_recommendations(Filter={"RESOURCE_ARN": real_arn})
    assert "Recommendations" in result, (
        f"expected a filtered list_recommendations call for an existing identity's ARN "
        f"to be accepted identically to the nonexistent-ARN case, got {result!r}"
    )


def _error(fn):
    """Call fn() and return its botocore error (code, message); raise if the call succeeds."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
