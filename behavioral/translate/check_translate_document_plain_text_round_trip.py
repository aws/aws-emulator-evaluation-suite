"""translate-document-plain-text-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "translate-document-plain-text-round-trip"
GROUP = "data-plane"
SERVICES = ["translate"]


@tags("axis:happy-path", "cap:unclassified", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """TranslateDocument round-trips a plain-text document: the response bytes decode to a
    genuine Spanish translation, not an echo of (or trivial mangling of) the source bytes."""
    translate = ctx.client("translate")
    original = "Good morning, colleague. The quarterly report is ready."
    resp = translate.translate_document(
        Document={"Content": original.encode("utf-8"), "ContentType": "text/plain"},
        SourceLanguageCode="en",
        TargetLanguageCode="es",
    )
    assert resp["SourceLanguageCode"] == "en", f"expected source en, got {resp['SourceLanguageCode']!r}"
    assert resp["TargetLanguageCode"] == "es", f"expected target es, got {resp['TargetLanguageCode']!r}"
    translated_bytes = resp["TranslatedDocument"]["Content"]
    assert isinstance(translated_bytes, (bytes, bytearray)), (
        f"expected TranslatedDocument.Content as bytes, got {type(translated_bytes)!r}"
    )
    translated_text = translated_bytes.decode("utf-8")
    assert len(translated_text) > 0, "translated document content is empty"
    assert translated_text != original, f"translated text is byte-identical to the source: {translated_text!r}"

    lowered = translated_text.lower()
    untranslated = [w for w in ("colleague", "quarterly", "report", "ready") if w in lowered]
    assert not untranslated, (
        f"English content words survived untranslated: {untranslated} in {translated_text!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
