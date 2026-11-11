"""glossary-term-create-missing-glossary-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "glossary-term-create-missing-glossary-rejected"
GROUP = "state-machine"
SERVICES = ["glue"]


def _error(fn):
    """Call fn() and return the (code, message) of the ClientError it raises. An unexpected
    success raises, so an emulator accepting what AWS refuses fails loudly."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected a rejection, but the call succeeded and returned {result!r}")


def _ignore_missing(fn):
    """Run a teardown call; a resource that is already gone is not a leak."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as err:
        if err.response["Error"]["Code"] != "EntityNotFoundException":
            raise


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateGlossaryTerm under a GlossaryIdentifier that names no glossary, and GetGlossary on it,
    raise EntityNotFoundException with the exact message; a term under a real glossary is created
    with its GlossaryId and Name.
    """
    glue = ctx.client("glue")

    bogus_glossary_id = ctx.unique_name("sim2real-missing-glossary-")
    term_name = ctx.unique_name("sim2real-term-")

    code, message = _error(
        lambda: glue.create_glossary_term(GlossaryIdentifier=bogus_glossary_id, Name=term_name)
    )
    assert code == "EntityNotFoundException", (
        f"expected CreateGlossaryTerm under a missing glossary to be refused with "
        f"EntityNotFoundException, got {code!r}"
    )
    expected = f'{{"Message":"Business glossary {bogus_glossary_id} not found."}}'
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: nothing was vivified under the bogus id.
    got_code, got_message = _error(lambda: glue.get_glossary(Identifier=bogus_glossary_id))
    assert got_code == "EntityNotFoundException", (
        f"expected GetGlossary on the bogus id to be EntityNotFoundException, got {got_code!r}"
    )
    assert got_message == expected, f"expected message {expected!r}, got {got_message!r}"

    # Positive control: the same CreateGlossaryTerm under a real glossary succeeds.
    glossary_id = glue.create_glossary(Name=ctx.unique_name("sim2real-glossary-"))["Id"]
    ctx.on_cleanup(lambda: _ignore_missing(lambda: glue.delete_glossary(Identifier=glossary_id)))
    term_id = glue.create_glossary_term(GlossaryIdentifier=glossary_id, Name=term_name)["Id"]
    ctx.on_cleanup(lambda: _ignore_missing(lambda: glue.delete_glossary_term(Identifier=term_id)))
    fetched = glue.get_glossary_term(Identifier=term_id)
    assert fetched["GlossaryId"] == glossary_id, (
        f"expected GlossaryId={glossary_id!r}, got {fetched.get('GlossaryId')!r}"
    )
    assert fetched["Name"] == term_name, f"expected Name={term_name!r}, got {fetched.get('Name')!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
