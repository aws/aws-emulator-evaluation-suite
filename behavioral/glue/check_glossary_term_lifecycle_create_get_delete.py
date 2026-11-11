"""glossary-term-lifecycle-create-get-delete."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "glossary-term-lifecycle-create-get-delete"
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


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GlossaryTerm transitions from created -> retrievable -> gone after DeleteGlossaryTerm, and a
    mutation (UpdateGlossaryTerm) against the deleted id fails the same way a read does."""
    glue = ctx.client("glue")
    glossary_name = ctx.unique_name("sim2real-glossary-")
    glossary_id = glue.create_glossary(Name=glossary_name)["Id"]
    ctx.on_cleanup(lambda: _ignore_missing(lambda: glue.delete_glossary(Identifier=glossary_id)))

    term_name = ctx.unique_name("sim2real-term-")
    created = glue.create_glossary_term(
        GlossaryIdentifier=glossary_id,
        Name=term_name,
        ShortDescription="short desc",
        LongDescription="long desc for the term",
    )
    term_id = created["Id"]
    assert created["GlossaryId"] == glossary_id, f"expected GlossaryId {glossary_id!r}, got {created['GlossaryId']!r}"
    assert created["Name"] == term_name, f"expected Name {term_name!r}, got {created['Name']!r}"

    ctx.on_cleanup(lambda: _ignore_missing(lambda: glue.delete_glossary_term(Identifier=term_id)))

    got = glue.get_glossary_term(Identifier=term_id)
    assert got["Id"] == term_id, f"expected Id {term_id!r}, got {got['Id']!r}"
    assert got["GlossaryId"] == glossary_id, f"expected GlossaryId {glossary_id!r}, got {got['GlossaryId']!r}"
    assert got["Name"] == term_name, f"expected Name {term_name!r}, got {got['Name']!r}"
    assert got["ShortDescription"] == "short desc", f"expected ShortDescription 'short desc', got {got['ShortDescription']!r}"
    assert got["LongDescription"] == "long desc for the term", (
        f"expected LongDescription 'long desc for the term', got {got['LongDescription']!r}"
    )

    glue.delete_glossary_term(Identifier=term_id)

    code, message = _error(lambda: glue.get_glossary_term(Identifier=term_id))
    assert code == "EntityNotFoundException", f"expected EntityNotFoundException from GetGlossaryTerm on deleted id, got {code!r}"
    expected = f'{{"Message":"Business glossary term {term_id} not found."}}'
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    code, message = _error(lambda: glue.update_glossary_term(Identifier=term_id, ShortDescription="post-delete update"))
    assert code == "EntityNotFoundException", (
        f"expected EntityNotFoundException from UpdateGlossaryTerm on deleted id, got {code!r}"
    )
    expected = f'{{"Message":"Business glossary term {term_id} not found."}}'
    assert message == expected, f"expected message {expected!r}, got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
