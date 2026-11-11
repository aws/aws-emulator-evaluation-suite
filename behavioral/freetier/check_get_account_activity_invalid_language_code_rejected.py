"""get-account-activity-invalid-language-code-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-account-activity-invalid-language-code-rejected"
GROUP = "error-semantics"
SERVICES = ["freetier"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetAccountActivity with languageCode "xx-XX" fails with ValidationException and the exact enum message, while
    a valid languageCode on the same nonexistent id gets ResourceNotFoundException "Activity not found"."""
    freetier = ctx.client("freetier")
    valid_but_nonexistent_id = "z" * 32

    error = _error(
        lambda: freetier.get_account_activity(
            activityId=valid_but_nonexistent_id, languageCode="xx-XX"
        )
    )
    assert error["Code"] == "ValidationException", error
    assert error["Message"] == (
        "1 validation error detected: Value 'xx-XX' at 'languageCode' failed to satisfy "
        "constraint: Member must satisfy enum value set: "
        "[zh-TW, en-US, zh-CN, tr-TR, pt-PT, it-IT, fr-FR, es-ES, de-DE, id-ID, ko-KR, ja-JP, en-GB]"
    ), error

    control = _error(
        lambda: freetier.get_account_activity(
            activityId=valid_but_nonexistent_id, languageCode="en-US"
        )
    )
    assert control["Code"] == "ResourceNotFoundException", control
    assert control["Message"] == "Activity not found", control


def _error(fn):
    """Call fn() and return its ClientError's Error dict; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
