"""glossary-term-update-nonexistent-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "glossary-term-update-nonexistent-rejected"
GROUP = "e2e"
SERVICES = ["glue"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateGlossaryTerm on an Identifier that matches no term is rejected with
    EntityNotFoundException, while updating a real term succeeds and GetGlossaryTerm reflects it."""
    glue = ctx.client("glue")

    bogus_id = "gt-" + ctx.unique_name("nonexistent").replace("_", "")[:20]
    code, message = _error(lambda: glue.update_glossary_term(Identifier=bogus_id, Name="ShouldNotApply"))
    assert code == "EntityNotFoundException", code
    expected = f'{{"Message":"Business glossary term {bogus_id} not found."}}'
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Positive control: updating a real term succeeds and the change is visible.
    glossary_name = ctx.unique_name("sim2real-behav-updctrl-gloss-")
    glossary = glue.create_glossary(Name=glossary_name)
    glossary_id = glossary["Id"]
    ctx.on_cleanup(lambda: _safe_delete_glossary(ctx, glossary_id))

    term = glue.create_glossary_term(GlossaryIdentifier=glossary_id, Name="OriginalName")
    term_id = term["Id"]
    ctx.on_cleanup(lambda: _safe_delete_term(ctx, term_id))

    glue.update_glossary_term(Identifier=term_id, Name="UpdatedName")

    fetched = glue.get_glossary_term(Identifier=term_id)
    assert fetched["Name"] == "UpdatedName", fetched["Name"]


# ===== helpers =====
def _safe_delete_term(ctx, term_id):
    from botocore.exceptions import ClientError

    glue = ctx.client("glue")
    try:
        glue.delete_glossary_term(Identifier=term_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "EntityNotFoundException":
            raise


def _safe_delete_glossary(ctx, glossary_id):
    from botocore.exceptions import ClientError

    glue = ctx.client("glue")
    try:
        glue.delete_glossary(Identifier=glossary_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "EntityNotFoundException":
            raise


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

