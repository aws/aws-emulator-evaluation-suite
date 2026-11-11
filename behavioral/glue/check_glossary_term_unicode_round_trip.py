"""glossary-term-unicode-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "glossary-term-unicode-round-trip"
GROUP = "representation"
SERVICES = ["glue"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A glossary term created with a unicode/multibyte name and a long description is
    returned byte-identical by GetGlossaryTerm -- not truncated, re-encoded, or mangled."""
    glue = ctx.client("glue")

    glossary_name = ctx.unique_name("sim2real-behav-gloss-")
    glossary = glue.create_glossary(Name=glossary_name, Description="behavioral fidelity glossary")
    glossary_id = glossary["Id"]
    ctx.on_cleanup(lambda: glue.delete_glossary(Identifier=glossary_id))

    term_name = "\u65e5\u672c\u8a9e\u7528\u8a9e\u30fbGl\u00fcck\u00df\u00e9\u00e8\u4e2d\u6587\u672f\u8bed-\U0001F600"
    long_description = (
        "\u00c9\u00e8\u00e9\u00ea\u4e2d\u6587\u63cf\u8ff0 " * 40
        + "end-of-description-marker-\U0001F680"
    )
    short_description = "\u65e5\u672c\u8a9e\u7c21\u6613\u8aac\u660e"

    created = glue.create_glossary_term(
        GlossaryIdentifier=glossary_id,
        Name=term_name,
        ShortDescription=short_description,
        LongDescription=long_description,
    )
    term_id = created["Id"]
    ctx.on_cleanup(lambda: glue.delete_glossary_term(Identifier=term_id))

    assert created["Name"] == term_name, (
        f"CreateGlossaryTerm echoed a mangled Name: expected {term_name!r}, got {created['Name']!r}"
    )
    assert created["ShortDescription"] == short_description, (
        f"CreateGlossaryTerm echoed a mangled ShortDescription: expected {short_description!r}, "
        f"got {created['ShortDescription']!r}"
    )
    assert created["LongDescription"] == long_description, (
        "CreateGlossaryTerm echoed a mangled LongDescription: expected "
        f"{long_description!r}, got {created['LongDescription']!r}"
    )

    fetched = glue.get_glossary_term(Identifier=term_id)
    assert fetched["Name"] == term_name, (
        f"unicode term name mangled on round-trip: expected {term_name!r}, got {fetched['Name']!r}"
    )
    assert fetched["ShortDescription"] == short_description, (
        f"unicode short description mangled on round-trip: expected {short_description!r}, "
        f"got {fetched['ShortDescription']!r}"
    )
    assert fetched["LongDescription"] == long_description, (
        "long unicode description not preserved byte-identical: expected "
        f"{long_description!r}, got {fetched['LongDescription']!r}"
    )
    assert fetched["GlossaryId"] == glossary_id, (
        f"GetGlossaryTerm returned wrong GlossaryId: expected {glossary_id!r}, got {fetched['GlossaryId']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
