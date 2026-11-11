"""list-types-invalid-visibility-filter-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-types-invalid-visibility-filter-rejected"
GROUP = "error-semantics"
SERVICES = ["cloudformation"]


@tags("axis:rejection", "cap:c5", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListTypes rejects an unrecognized Visibility value with ValidationException, while
    a valid Visibility value combined with a well-formed Category filter succeeds and
    returns a non-empty catalog."""
    from botocore.exceptions import ClientError

    cfn = ctx.client("cloudformation")

    try:
        cfn.list_types(Visibility="NOT_A_REAL_VISIBILITY", Filters={"Category": "AWS_TYPES"})
        raise AssertionError(
            "expected ValidationException for an unrecognized Visibility value"
        )
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        assert code == "ValidationError", f"unexpected error code: {code}"
        message = exc.response["Error"].get("Message")
        assert message == (
            "1 validation error detected: Value 'NOT_A_REAL_VISIBILITY' at 'visibility' "
            "failed to satisfy constraint: Member must satisfy enum value set: [PRIVATE, PUBLIC]"
        ), f"unexpected ValidationError message {message!r}"

    # Positive control: the same base filter with a valid Visibility value is well-formed
    # and must succeed with real, correctly-classified results — not merely a non-empty list.
    control = cfn.list_types(
        Visibility="PUBLIC", Filters={"Category": "AWS_TYPES"}, MaxResults=10
    )
    summaries = control["TypeSummaries"]
    assert len(summaries) > 0, f"expected a non-empty AWS_TYPES catalog, got: {summaries}"
    assert all(t["TypeName"].startswith("AWS::") for t in summaries), (
        f"AWS_TYPES catalog entry not AWS-native: {summaries}"
    )
    assert all(t.get("PublisherIdentity", "AWS") == "AWS" for t in summaries), (
        f"AWS_TYPES catalog entry not published under PublisherIdentity=AWS: {summaries}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

