"""translate-text-profanity-masking-setting."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "translate-text-profanity-masking-setting"
GROUP = "data-plane"
SERVICES = ["translate"]

_GRAWLIX = "?$#@$"


@tags("axis:happy-path", "cap:unclassified", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Settings.Profanity=MASK replaces profane words with the grawlix string in the output."""
    translate = ctx.client("translate")
    profane_text = "Esta mierda es inaceptable."

    masked = translate.translate_text(
        Text=profane_text,
        SourceLanguageCode="es",
        TargetLanguageCode="en",
        Settings={"Profanity": "MASK"},
    )
    assert masked["AppliedSettings"]["Profanity"] == "MASK", (
        f"expected AppliedSettings.Profanity=MASK, got {masked.get('AppliedSettings')}"
    )
    assert _GRAWLIX in masked["TranslatedText"], (
        f"expected grawlix {_GRAWLIX!r} in masked translation, got {masked['TranslatedText']!r}"
    )

    unmasked = translate.translate_text(
        Text=profane_text,
        SourceLanguageCode="es",
        TargetLanguageCode="en",
    )
    assert "AppliedSettings" not in unmasked or unmasked.get("AppliedSettings", {}).get("Profanity") != "MASK", (
        f"expected no MASK profanity setting applied without Settings, got {unmasked.get('AppliedSettings')}"
    )
    assert _GRAWLIX not in unmasked["TranslatedText"], (
        f"expected no grawlix {_GRAWLIX!r} in unmasked translation, got {unmasked['TranslatedText']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
