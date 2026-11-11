"""glossary-term-unicode-name-description-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "glossary-term-unicode-name-description-round-trip"
GROUP = "representation"
SERVICES = ["glue"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Unicode in a glossary term's Name/ShortDescription/LongDescription survives Create->Get byte-for-byte."""
    glue = ctx.client("glue")

    glossary = glue.create_glossary(Name=ctx.unique_name("sim2real-glossary-"))
    glossary_id = glossary["Id"]
    ctx.on_cleanup(lambda: glue.delete_glossary(Identifier=glossary_id))

    unicode_name = "术语-Ключ-Ωμέγα-café-🔑"
    unicode_short = "Short décomposition: 日本語のテスト単語 — naïve café façade 🎯"
    unicode_long = (
        "Long-form unicode description spanning scripts: "
        "中文测试内容, Русский текст, Ελληνικό κείμενο, français accentué, "
        "emoji sequence 🚀🔥🎉, and mathematical symbols ∑∫√≈≠. "
    ) * 3

    term = glue.create_glossary_term(
        GlossaryIdentifier=glossary_id,
        Name=unicode_name,
        ShortDescription=unicode_short,
        LongDescription=unicode_long,
    )
    term_id = term["Id"]
    ctx.on_cleanup(lambda: glue.delete_glossary_term(Identifier=term_id))

    # Create response should already echo the values...
    assert term["Name"] == unicode_name, f"create echo mangled Name: expected {unicode_name!r}, got {term['Name']!r}"
    assert term["ShortDescription"] == unicode_short, (
        f"create echo mangled ShortDescription: expected {unicode_short!r}, got {term['ShortDescription']!r}"
    )
    assert term["LongDescription"] == unicode_long, (
        f"create echo mangled LongDescription: expected {unicode_long!r}, got {term['LongDescription']!r}"
    )

    # ...but the fidelity signal we actually care about is that Get returns the
    # exact same bytes back out of storage, not just an echo of the request.
    fetched = glue.get_glossary_term(Identifier=term_id)
    assert fetched["Name"] == unicode_name, (
        f"unicode term Name not preserved byte-identical: expected {unicode_name!r}, got {fetched['Name']!r}"
    )
    assert fetched["ShortDescription"] == unicode_short, (
        f"unicode ShortDescription not preserved byte-identical: expected {unicode_short!r}, got {fetched['ShortDescription']!r}"
    )
    assert fetched["LongDescription"] == unicode_long, (
        f"unicode LongDescription not preserved byte-identical: expected {unicode_long!r}, got {fetched['LongDescription']!r}"
    )
    assert fetched["GlossaryId"] == glossary_id, (
        f"GlossaryId mismatch on term fetch: expected {glossary_id!r}, got {fetched['GlossaryId']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
