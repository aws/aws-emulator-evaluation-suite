"""get-use-case-for-model-access-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-use-case-for-model-access-not-found"
GROUP = "error-semantics"
SERVICES = ["bedrock"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetUseCaseForModelAccess for a caller with no recorded use-case form returns
    ResourceNotFoundException rather than an empty success payload.
    """
    bedrock = ctx.client("bedrock")
    try:
        bedrock.get_use_case_for_model_access()
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        message = exc.response["Error"].get("Message")
        assert code == "ResourceNotFoundException", (
            f"expected ResourceNotFoundException for an unregistered use-case form, got {code!r}"
        )
        expected = (
            "You have not filled out the request form. "
            "Fill out the form before getting access."
        )
        assert message == expected, f"expected message {expected!r}, got {message!r}"
        return
    raise AssertionError(
        "this account already has a recorded model-access use-case form; that is a "
        "one-time, account-wide state with no API to unset it, so the not-found path "
        "cannot be exercised from this account -- would need a genuinely fresh account"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
