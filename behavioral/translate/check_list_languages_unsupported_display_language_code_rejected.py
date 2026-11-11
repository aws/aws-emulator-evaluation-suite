"""list-languages-unsupported-display-language-code-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-languages-unsupported-display-language-code-rejected"
GROUP = "overly-permissive"
SERVICES = ["translate"]


def _client_error(fn):
    """Call fn(); return its botocore error code. An unexpected SUCCESS raises, because a target
    ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(
        f"real AWS rejects DisplayLanguageCode='zz', but the target SUCCEEDED and returned {result!r}"
    )


@tags("axis:rejection", "cap:c5", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListLanguages rejects a display-language code that isn't one of the fixed enum of supported
    display languages (de|en|es|fr|it|ja|ko|pt|zh|zh-TW) -- the service validates the enum member and
    rejects an out-of-set value rather than silently falling back to a default."""
    translate = ctx.client("translate")

    code, message = _client_error(lambda: translate.list_languages(DisplayLanguageCode="zz"))
    assert code == "ValidationException", (
        f"expected ValidationException for an out-of-set DisplayLanguageCode, got {code!r}"
    )
    expected = (
        "1 validation error detected: Value 'zz' at 'displayLanguageCode' failed to satisfy constraint: "
        "Member must satisfy enum value set: [de, zh-TW, pt, ko, en, it, fr, zh, es, ja]"
    )
    assert message == expected, f"expected enum validation message {expected!r}, got {message!r}"

    # positive control: a supported display language code succeeds and returns known languages
    resp = translate.list_languages(DisplayLanguageCode="en")
    languages = {lang["LanguageCode"]: lang["LanguageName"] for lang in resp["Languages"]}
    assert languages.get("es") == "Spanish", f"expected 'es' -> 'Spanish', got {languages.get('es')!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
