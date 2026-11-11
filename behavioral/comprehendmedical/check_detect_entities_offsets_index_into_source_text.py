"""detect-entities-offsets-index-into-source-text."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "detect-entities-offsets-index-into-source-text"
GROUP = "invariant"
SERVICES = ["comprehendmedical"]


@tags("axis:happy-path", "cap:unclassified", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """Every entity's BeginOffset/EndOffset slice the original input text to exactly its Text."""
    cm = ctx.client("comprehendmedical")
    text = (
        "The 68-year-old male patient was prescribed 10 mg of lisinopril once daily for "
        "hypertension and denies any history of diabetes."
    )
    resp = cm.detect_entities_v2(Text=text)
    entities = resp["Entities"]
    assert len(entities) > 0, "expected at least one entity to validate offsets against"

    for entity in entities:
        begin, end = entity["BeginOffset"], entity["EndOffset"]
        sliced = text[begin:end]
        assert sliced == entity["Text"], (
            f"entity Text {entity['Text']!r} does not match text[{begin}:{end}]={sliced!r}"
        )
        for attribute in entity.get("Attributes", []):
            a_begin, a_end = attribute["BeginOffset"], attribute["EndOffset"]
            a_sliced = text[a_begin:a_end]
            assert a_sliced == attribute["Text"], (
                f"attribute Text {attribute['Text']!r} does not match text[{a_begin}:{a_end}]={a_sliced!r}"
            )

    # Representation depth: BeginOffset/EndOffset are documented as UTF-8 *code point* offsets.
    # Python str indexing is also code-point based, so if an emulator instead counted UTF-8 BYTES
    # (or clamped to ASCII), offsets after a multi-byte character would drift out of alignment and
    # this slice-equality check would catch it -- unlike the ASCII-only text above.
    unicode_text = (
        "Dr. José Muñoz saw the patient at the café clinic and prescribed metformin 500 mg "
        "twice daily for type 2 diabetes."
    )
    unicode_resp = cm.detect_entities_v2(Text=unicode_text)
    unicode_entities = unicode_resp["Entities"]
    assert len(unicode_entities) > 0, "expected at least one entity in the multi-byte-prefixed text"

    for entity in unicode_entities:
        begin, end = entity["BeginOffset"], entity["EndOffset"]
        sliced = unicode_text[begin:end]
        assert sliced == entity["Text"], (
            f"[unicode] entity Text {entity['Text']!r} does not match "
            f"unicode_text[{begin}:{end}]={sliced!r} -- offsets are not aligned to UTF-8 code points"
        )

    cafe_end = unicode_text.index("café") + len("café")
    assert any(e["BeginOffset"] >= cafe_end for e in unicode_entities), (
        "expected at least one entity positioned after the multi-byte 'café' span, to actually "
        "exercise offset alignment past a multi-byte prefix"
    )



if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
