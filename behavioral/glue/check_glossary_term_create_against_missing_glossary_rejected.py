"""glossary-term-create-against-missing-glossary-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "glossary-term-create-against-missing-glossary-rejected"
GROUP = "state-machine"
SERVICES = ["glue"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateGlossaryTerm against a glossary identifier that no longer exists is rejected with
    EntityNotFoundException and creates no dangling term.
    """
    glue = ctx.client("glue")
    glossary_name = ctx.unique_name("sim2real-behav-glossary-missingparent-")

    # Create a real glossary, then delete it so its Id is a definitively-gone identifier.
    glossary_id = glue.create_glossary(Name=glossary_name)["Id"]
    ctx.on_cleanup(lambda: _delete_glossary_ignore_missing(glue, glossary_id))
    glue.delete_glossary(Identifier=glossary_id)

    # Break exactly one thing: create a term under a glossary identifier that no longer exists.
    code, message = _error(
        lambda: glue.create_glossary_term(
            GlossaryIdentifier=glossary_id, Name=ctx.unique_name("sim2real-behav-term-orphan-")
        )
    )
    assert code == "EntityNotFoundException", (
        f"expected EntityNotFoundException creating a term under a deleted glossary, got {code!r}"
    )
    expected = f'{{"Message":"Business glossary {glossary_id} not found."}}'
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: the glossary is still gone (the rejected call didn't resurrect it).
    still_gone, still_gone_message = _error(lambda: glue.get_glossary(Identifier=glossary_id))
    assert still_gone == "EntityNotFoundException", (
        f"expected the deleted glossary {glossary_id!r} to still read as gone, got {still_gone!r}"
    )
    expected = f'{{"Message":"Business glossary {glossary_id} not found."}}'
    assert still_gone_message == expected, f"expected message {expected!r}, got {still_gone_message!r}"

    # Positive control (same file): CreateGlossaryTerm against a live glossary succeeds.
    live_name = ctx.unique_name("sim2real-behav-glossary-missingparent-live-")
    live_id = glue.create_glossary(Name=live_name)["Id"]
    ctx.on_cleanup(lambda: _delete_glossary_ignore_missing(glue, live_id))
    live_term_id = glue.create_glossary_term(
        GlossaryIdentifier=live_id, Name=ctx.unique_name("sim2real-behav-term-live-")
    )["Id"]
    ctx.on_cleanup(lambda: _delete_term_ignore_missing(glue, live_term_id))
    got_term = glue.get_glossary_term(Identifier=live_term_id)
    assert got_term["GlossaryId"] == live_id, (
        f"expected positive-control term's GlossaryId to be {live_id!r}, got {got_term.get('GlossaryId')!r}"
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


def _delete_glossary_ignore_missing(glue, glossary_id: str) -> None:
    from botocore.exceptions import ClientError

    try:
        glue.delete_glossary(Identifier=glossary_id)
    except ClientError as e:
        if e.response["Error"]["Code"] not in ("EntityNotFoundException", "ConflictException"):
            raise


def _delete_term_ignore_missing(glue, term_id: str) -> None:
    from botocore.exceptions import ClientError

    try:
        glue.delete_glossary_term(Identifier=term_id)
    except ClientError as e:
        if e.response["Error"]["Code"] != "EntityNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
