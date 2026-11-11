"""list-account-activities-invalid-language-code-error."""

from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-account-activities-invalid-language-code-error"
GROUP = "error-semantics"
SERVICES = ["freetier"]

_EXPECTED_MESSAGE = (
    "1 validation error detected: Value 'xx-XX' at 'languageCode' failed to satisfy constraint: "
    "Member must satisfy enum value set: "
    "[zh-TW, en-US, zh-CN, tr-TR, pt-PT, it-IT, fr-FR, es-ES, de-DE, id-ID, ko-KR, ja-JP, en-GB]"
)


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because an emulator
    ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as err:
        return err.response.get("Error", {})
    raise AssertionError(
        f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}"
    )


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListAccountActivities with languageCode "xx-XX" fails with ValidationException and the exact enum message,
    while the same call with a modeled languageCode is accepted."""
    freetier = ctx.client("freetier")

    # Positive control: the same call shape, a modeled languageCode.
    freetier.list_account_activities(languageCode="en-US")

    error = _client_error(
        lambda: freetier.list_account_activities(languageCode="xx-XX")
    )
    assert error.get("Code") == "ValidationException", (
        f'expected ValidationException for languageCode="xx-XX", got '
        f"{error.get('Code')!r} (message: {error.get('Message')!r})"
    )
    assert error.get("Message") == _EXPECTED_MESSAGE, error.get("Message")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
