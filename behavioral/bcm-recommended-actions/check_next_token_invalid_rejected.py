"""next-token-invalid-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "next-token-invalid-rejected"
GROUP = "overly-permissive"
SERVICES = ["bcm-recommended-actions"]


def _error_response(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as err:
        return err.response
    return None


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A syntactically-valid but semantically-garbage nextToken is rejected with ValidationException."""
    client = ctx.client("bcm-recommended-actions")

    garbage_token = "not-a-real-continuation-token-0123456789"
    error = _error_response(lambda: client.list_recommended_actions(nextToken=garbage_token))

    assert error is not None, "expected ListRecommendedActions to reject an invalid nextToken"
    assert error["Error"]["Code"] == "ValidationException", (
        f"expected ValidationException, got {error['Error']['Code']}: {error['Error'].get('Message')}"
    )
    # The trailing number is a function of the token bytes, so a fixed token yields a fixed message.
    expected_message = (
        "Pagination token exception in operation 'ListRecommendedActions': "
        "invalid payload wrapping schema -24949"
    )
    message = error["Error"].get("Message")
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Positive control: the same operation, without the broken token, still works.
    control = client.list_recommended_actions()
    assert isinstance(control["recommendedActions"], list)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
