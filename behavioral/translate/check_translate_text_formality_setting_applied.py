"""translate-text-formality-setting-applied."""
from __future__ import annotations

import re

from behavioral_harness import tags

CHECK = "translate-text-formality-setting-applied"
GROUP = "data-plane"
SERVICES = ["translate"]


@tags("axis:happy-path", "cap:unclassified", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Settings.Formality changes German pronoun choice and is echoed back in AppliedSettings."""
    translate = ctx.client("translate")
    text = "How are you today? I hope you can help me."

    formal = translate.translate_text(
        Text=text,
        SourceLanguageCode="en",
        TargetLanguageCode="de",
        Settings={"Formality": "FORMAL"},
    )
    informal = translate.translate_text(
        Text=text,
        SourceLanguageCode="en",
        TargetLanguageCode="de",
        Settings={"Formality": "INFORMAL"},
    )

    assert formal["AppliedSettings"]["Formality"] == "FORMAL", formal.get("AppliedSettings")
    assert informal["AppliedSettings"]["Formality"] == "INFORMAL", informal.get("AppliedSettings")
    assert formal["TranslatedText"] != informal["TranslatedText"], (
        f"formal={formal['TranslatedText']!r} informal={informal['TranslatedText']!r}"
    )
    assert re.search(r"\bSie\b|\bIhnen\b", formal["TranslatedText"]), (
        f"expected a formal German pronoun (Sie/Ihnen), got {formal['TranslatedText']!r}"
    )
    assert not re.search(r"\bSie\b|\bIhnen\b", informal["TranslatedText"]), (
        f"informal output should not carry the formal pronoun, got {informal['TranslatedText']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
