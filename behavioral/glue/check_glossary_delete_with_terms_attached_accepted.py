"""glossary-delete-with-terms-attached-accepted."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "glossary-delete-with-terms-attached-accepted"
GROUP = "state-machine"
SERVICES = ["glue"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteGlossary on a glossary with a term succeeds; GetGlossary and UpdateGlossary then raise
    EntityNotFoundException, the term stays gettable with the old GlossaryId, and after
    DeleteGlossaryTerm GetGlossaryTerm raises EntityNotFoundException.
    """
    glue = ctx.client("glue")

    glossary_name = ctx.unique_name("sim2real-glossary-")
    glossary_id = glue.create_glossary(Name=glossary_name)["Id"]

    term_name = ctx.unique_name("sim2real-term-")
    term_id = glue.create_glossary_term(GlossaryIdentifier=glossary_id, Name=term_name)["Id"]

    ctx.on_cleanup(lambda: _ignore_missing(lambda: glue.delete_glossary(Identifier=glossary_id)))
    ctx.on_cleanup(lambda: _ignore_missing(lambda: glue.delete_glossary_term(Identifier=term_id)))

    # DeleteGlossary while a term is still attached is NOT rejected on real AWS.
    glue.delete_glossary(Identifier=glossary_id)

    # Independent read at the destination, via a different operation than the mutation: the
    # glossary itself is gone.
    gone_code, gone_message = _error(lambda: glue.get_glossary(Identifier=glossary_id))
    assert gone_code == "EntityNotFoundException", (
        f"expected the deleted glossary to 404, got {gone_code}"
    )
    expected = f'{{"Message":"Business glossary {glossary_id} not found."}}'
    assert gone_message == expected, f"expected message {expected!r}, got {gone_message!r}"

    # The term was not cascade-deleted: it is orphaned, still independently gettable, and its
    # GlossaryId still points at the now-nonexistent parent.
    orphaned_term = glue.get_glossary_term(Identifier=term_id)
    assert orphaned_term["Id"] == term_id, f"expected orphan term Id {term_id}, got {orphaned_term['Id']}"
    assert orphaned_term["GlossaryId"] == glossary_id, (
        f"expected orphan term to still point at dead parent {glossary_id}, "
        f"got {orphaned_term['GlossaryId']}"
    )

    # A mutation on the dead glossary id is rejected (not silently accepted, not a 500).
    dead_mutation_code, dead_mutation_message = _error(
        lambda: glue.update_glossary(Identifier=glossary_id, Description="should-not-apply")
    )
    assert dead_mutation_code == "EntityNotFoundException", (
        f"expected UpdateGlossary on the deleted glossary id to 404, got {dead_mutation_code}"
    )
    expected = f'{{"Message":"Business glossary {glossary_id} not found."}}'
    assert dead_mutation_message == expected, f"expected message {expected!r}, got {dead_mutation_message!r}"

    # Explicitly delete the orphaned term and prove it gone by an independent read.
    glue.delete_glossary_term(Identifier=term_id)
    term_gone_code, term_gone_message = _error(lambda: glue.get_glossary_term(Identifier=term_id))
    assert term_gone_code == "EntityNotFoundException", (
        f"expected the deleted orphan term to 404, got {term_gone_code}"
    )
    expected = f'{{"Message":"Business glossary term {term_id} not found."}}'
    assert term_gone_message == expected, f"expected message {expected!r}, got {term_gone_message!r}"


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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
