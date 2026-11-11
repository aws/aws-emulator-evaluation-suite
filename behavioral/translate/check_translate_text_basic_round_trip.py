"""translate-text-basic-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "translate-text-basic-round-trip"
GROUP = "data-plane"
SERVICES = ["translate"]


@tags("axis:happy-path", "cap:unclassified", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """TranslateText round-trips en->es->en: the intermediate is real Spanish (not the English
    text smuggled through untouched), and translating back recovers the source's key content
    words, which a pass-through or tag-prepending stub cannot do in both directions at once."""
    translate = ctx.client("translate")
    source_text = "Hello, how are you doing today?"
    to_es = translate.translate_text(
        Text=source_text,
        SourceLanguageCode="en",
        TargetLanguageCode="es",
    )
    assert to_es["SourceLanguageCode"] == "en"
    assert to_es["TargetLanguageCode"] == "es"
    spanish = to_es["TranslatedText"]
    assert isinstance(spanish, str) and len(spanish) > 0
    assert spanish != source_text
    assert source_text not in spanish, (
        f"expected genuine Spanish output, got the English source smuggled through: {spanish!r}"
    )

    back_to_en = translate.translate_text(
        Text=spanish,
        SourceLanguageCode="es",
        TargetLanguageCode="en",
    )
    assert back_to_en["SourceLanguageCode"] == "es"
    assert back_to_en["TargetLanguageCode"] == "en"
    round_tripped = back_to_en["TranslatedText"].lower()
    assert spanish not in round_tripped, (
        f"expected the reverse leg to translate, not smuggle the Spanish through: {round_tripped!r}"
    )
    for word in ("how", "today"):
        assert word in round_tripped, (
            f"round trip lost key content word {word!r}: got {round_tripped!r} from {spanish!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
