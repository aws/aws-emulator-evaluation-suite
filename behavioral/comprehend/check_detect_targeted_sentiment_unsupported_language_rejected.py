"""detect-targeted-sentiment-unsupported-language-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "detect-targeted-sentiment-unsupported-language-rejected"
GROUP = "overly-permissive"
SERVICES = ["comprehend"]


def _error(fn):
    """Call fn(), which must fail; return its botocore error (code, message). An unexpected
    SUCCESS raises, so a target that accepts what AWS refuses is never read as a mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response["Error"]
        return error["Code"], error.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:unclassified", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """DetectTargetedSentiment with a LanguageCode valid elsewhere in Comprehend but not English fails with
    ValidationException and its exact message, while the same text in English finds entities."""
    comprehend = ctx.client("comprehend")
    # Targeted sentiment supports English only, even though "fr" is a generally valid LanguageCode
    # enum value accepted by other Comprehend operations.
    # https://docs.aws.amazon.com/comprehend/latest/dg/supported-languages.html
    french_text = "La batterie de cet ordinateur est incroyable, mais l'ecran est decevant."

    code, message = _error(
        lambda: comprehend.detect_targeted_sentiment(Text=french_text, LanguageCode="fr")
    )
    assert code == "ValidationException", f"unexpected error code: {code!r}"
    # AWS's message has no space between 'languageCode' and "failed".
    expected = "Value 'fr' at 'languageCode'failed to satisfy constraint: Member must satisfy enum value set: [en]"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Positive control: the same operation with English text succeeds.
    resp = comprehend.detect_targeted_sentiment(
        Text="The battery on this laptop is amazing, but the screen is disappointing.",
        LanguageCode="en",
    )
    assert resp["Entities"], f"expected the English positive control to find entities: {resp}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

