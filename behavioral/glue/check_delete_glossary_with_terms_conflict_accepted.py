"""delete-glossary-with-terms-conflict-accepted."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-glossary-with-terms-conflict-accepted"
GROUP = "negative-classes"
SERVICES = ["glue"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteGlossary on a glossary with an attached, indexed term succeeds (no ConflictException) and
    does not cascade: GetGlossary 404s while the term stays gettable and listed under its GlossaryId."""
    glue = ctx.client("glue")
    if not hasattr(glue, "create_glossary"):
        raise AssertionError(
            "installed botocore has no create_glossary operation (AWS Glue "
            "Data Catalog business glossaries API is newer than this SDK "
            "build)"
        )

    glossary_id = glue.create_glossary(Name=ctx.unique_name("sim2real-glossary-"))["Id"]
    term_id = glue.create_glossary_term(
        GlossaryIdentifier=glossary_id, Name=ctx.unique_name("sim2real-term-")
    )["Id"]

    def _cleanup():
        # Both may already be gone: the body deletes the glossary and the term deliberately.
        try:
            glue.delete_glossary_term(Identifier=term_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "EntityNotFoundException":
                raise
        try:
            glue.delete_glossary(Identifier=glossary_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "EntityNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)

    # Demonstrated precondition: the term is actually indexed as attached
    # before we delete the glossary out from under it.
    _poll_until(
        lambda: {t["Id"] for t in glue.list_glossary_terms(GlossaryIdentifier=glossary_id).get("Items", [])},
        lambda ids: term_id in ids,
        timeout_s=60,
        interval_s=3,
    )

    # DeleteGlossary with an attached, indexed term must SUCCEED (not raise).
    # Real AWS does not enforce the ConflictException the API docs describe.
    glue.delete_glossary(Identifier=glossary_id)

    # Effect: the glossary itself is now gone, via an independent read
    # (GetGlossary, a different operation than the DeleteGlossary that ran).
    gone_code, gone_message = _error_code(lambda: glue.get_glossary(Identifier=glossary_id))
    assert gone_code == "EntityNotFoundException", (
        f"expected GetGlossary on the just-deleted glossary {glossary_id!r} to raise "
        f"EntityNotFoundException, got error code {gone_code!r}"
    )
    # AWS returns the JSON error body as this refusal's message.
    expected = f'{{"Message":"Business glossary {glossary_id} not found."}}'
    assert gone_message == expected, f"expected {expected!r}, got {gone_message!r}"

    # The term is orphaned, not cascade-deleted: still independently
    # gettable by Id, and its GlossaryId still points at the now-gone
    # parent -- the delete did not rewrite or clear it.
    orphan = glue.get_glossary_term(Identifier=term_id)
    assert orphan["Id"] == term_id, (
        f"expected GetGlossaryTerm({term_id!r}) to return that same term id, got "
        f"{orphan.get('Id')!r}"
    )
    assert orphan["GlossaryId"] == glossary_id, (
        f"expected the orphaned term's GlossaryId to still point at the deleted "
        f"glossary {glossary_id!r}, got {orphan.get('GlossaryId')!r}"
    )

    # Second independent observable of the orphan, on a different operation
    # again: ListGlossaryTerms scoped to the now-deleted parent still lists
    # the orphan too -- the deletion did not detach it from the listing
    # index either, only removed the parent glossary record itself.
    orphan_listing = glue.list_glossary_terms(GlossaryIdentifier=glossary_id).get("Items", [])
    assert term_id in {t["Id"] for t in orphan_listing}, (
        f"expected ListGlossaryTerms(GlossaryIdentifier={glossary_id!r}) to still list the "
        f"orphaned term {term_id!r} even though its parent glossary is gone, got "
        f"{orphan_listing!r}"
    )

    # Delete the orphan explicitly and prove it is gone with an independent read; a second
    # DeleteGlossaryTerm on the gone id is an idempotent no-op, not a 404.
    glue.delete_glossary_term(Identifier=term_id)
    term_gone_code, term_gone_message = _error_code(lambda: glue.get_glossary_term(Identifier=term_id))
    assert term_gone_code == "EntityNotFoundException", (
        f"expected GetGlossaryTerm on the just-deleted orphan term {term_id!r} to raise "
        f"EntityNotFoundException, got error code {term_gone_code!r}"
    )
    expected = f'{{"Message":"Business glossary term {term_id} not found."}}'
    assert term_gone_message == expected, f"expected {expected!r}, got {term_gone_message!r}"
    glue.delete_glossary_term(Identifier=term_id)  # idempotent no-op, must not raise


# ===== helpers =====
def _error_code(fn):
    """Call fn(); return its botocore (code, message). An unexpected success raises rather than
    reading as an error-code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code"), exc.response.get("Error", {}).get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while not predicate(value):
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout_s}s, last value={value!r}")
        time.sleep(interval_s)
        value = probe()
    return value


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
