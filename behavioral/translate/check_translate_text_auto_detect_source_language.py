"""translate-text-auto-detect-source-language."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "translate-text-auto-detect-source-language"
GROUP = "data-plane"
SERVICES = ["translate"]


@tags("axis:happy-path", "cap:unclassified", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """SourceLanguageCode='auto' detects the actual source language per input, not a fixed guess."""
    translate = ctx.client("translate")

    french_text = "Bonjour, comment allez-vous aujourd'hui?"
    resp_fr = translate.translate_text(
        Text=french_text,
        SourceLanguageCode="auto",
        TargetLanguageCode="en",
    )
    assert resp_fr["SourceLanguageCode"] == "fr", (
        f"expected auto-detect to identify French, got {resp_fr['SourceLanguageCode']!r}"
    )
    assert resp_fr["TargetLanguageCode"] == "en", (
        f"expected target language 'en', got {resp_fr['TargetLanguageCode']!r}"
    )
    translated_fr = resp_fr["TranslatedText"]
    assert isinstance(translated_fr, str) and len(translated_fr) > 0, (
        f"expected non-empty translated text, got {translated_fr!r}"
    )
    assert translated_fr != french_text, "expected translated text to differ from the French source"

    german_text = "Guten Tag, wie geht es Ihnen heute?"
    resp_de = translate.translate_text(
        Text=german_text,
        SourceLanguageCode="auto",
        TargetLanguageCode="en",
    )
    assert resp_de["SourceLanguageCode"] == "de", (
        f"expected auto-detect to identify German, got {resp_de['SourceLanguageCode']!r}"
    )
    assert resp_de["SourceLanguageCode"] != resp_fr["SourceLanguageCode"], (
        "auto-detect returned the same source language for distinct French and German inputs "
        f"({resp_de['SourceLanguageCode']!r})"
    )
    translated_de = resp_de["TranslatedText"]
    assert isinstance(translated_de, str) and len(translated_de) > 0, (
        f"expected non-empty translated text, got {translated_de!r}"
    )
    assert translated_de != german_text, "expected translated text to differ from the German source"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
