"""translate-text-unsupported-language-pair-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "translate-text-unsupported-language-pair-rejected"
GROUP = "overly-permissive"
SERVICES = ["translate"]


def _client_error(fn):
    try:
        resp = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected rejection, call succeeded with {resp!r}")


@tags("axis:rejection", "cap:unclassified", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """TranslateText rejects a syntactically valid but nonexistent target language code."""
    translate = ctx.client("translate")

    code, message = _client_error(
        lambda: translate.translate_text(
            Text="hello there",
            SourceLanguageCode="en",
            TargetLanguageCode="zz",
        )
    )
    assert code == "UnsupportedLanguagePairException", f"expected UnsupportedLanguagePairException, got {code}"
    assert message == "Unsupported language pair: en to zz.", f"expected the language-pair message, got {message!r}"

    # positive control: the same call with a real target language succeeds
    resp = translate.translate_text(
        Text="hello there",
        SourceLanguageCode="en",
        TargetLanguageCode="es",
    )
    assert len(resp["TranslatedText"]) > 0, f"expected non-empty translation, got {resp['TranslatedText']!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
