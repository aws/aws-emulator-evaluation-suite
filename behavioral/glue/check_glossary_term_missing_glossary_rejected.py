"""glossary-term-missing-glossary-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "glossary-term-missing-glossary-rejected"
GROUP = "representation"
SERVICES = ["glue"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateGlossaryTerm against a GlossaryIdentifier that does not exist is rejected
    with EntityNotFoundException, the term is not created, and a positive control
    (a real glossary) still succeeds in the same run."""
    glue = ctx.client("glue")

    bogus_glossary_id = "gl-" + ctx.unique_name("nonexistent").replace("_", "")[:20]

    code, message = _error(
        lambda: glue.create_glossary_term(GlossaryIdentifier=bogus_glossary_id, Name="OrphanTerm")
    )
    assert code == "EntityNotFoundException", f"expected EntityNotFoundException, got {code!r}"
    expected = f'{{"Message":"Business glossary {bogus_glossary_id} not found."}}'
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: the fabricated glossary id must not resolve to anything real.
    get_code, get_code_message = _error(lambda: glue.get_glossary(Identifier=bogus_glossary_id))
    assert get_code == "EntityNotFoundException", f"expected EntityNotFoundException, got {get_code!r}"
    expected = f'{{"Message":"Business glossary {bogus_glossary_id} not found."}}'
    assert get_code_message == expected, f"expected message {expected!r}, got {get_code_message!r}"

    # Positive control: the same call against a real glossary succeeds.
    glossary_name = ctx.unique_name("sim2real-behav-negctrl-gloss-")
    glossary = glue.create_glossary(Name=glossary_name)
    glossary_id = glossary["Id"]
    ctx.on_cleanup(lambda: glue.delete_glossary(Identifier=glossary_id))

    term = glue.create_glossary_term(GlossaryIdentifier=glossary_id, Name="RealTerm")
    term_id = term["Id"]
    ctx.on_cleanup(lambda: glue.delete_glossary_term(Identifier=term_id))

    fetched = glue.get_glossary_term(Identifier=term_id)
    assert fetched["Name"] == "RealTerm", f"expected Name='RealTerm', got {fetched.get('Name')!r}"
    assert fetched["GlossaryId"] == glossary_id, (
        f"expected GlossaryId={glossary_id!r}, got {fetched.get('GlossaryId')!r}"
    )


def _error(fn):
    """Call fn() and return the (code, message) of the ClientError it raises. An unexpected
    success raises, so an emulator accepting what AWS refuses fails loudly."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected a rejection, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
