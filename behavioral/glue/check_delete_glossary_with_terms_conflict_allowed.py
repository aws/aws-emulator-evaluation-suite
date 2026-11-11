"""delete-glossary-with-terms-conflict-allowed."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "delete-glossary-with-terms-conflict-allowed"
GROUP = "error-semantics"
SERVICES = ["glue"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteGlossary on a glossary with an attached term succeeds without ConflictException and
    does not cascade: the glossary is gone, while the term remains gettable with its GlossaryId."""
    glue = ctx.client("glue")

    glossary_id = glue.create_glossary(Name=ctx.unique_name("sim2real-glossary-"))["Id"]
    ctx.on_cleanup(lambda: _safe_delete_glossary(ctx, glossary_id))
    term_id = glue.create_glossary_term(
        GlossaryIdentifier=glossary_id, Name=ctx.unique_name("sim2real-term-")
    )["Id"]
    ctx.on_cleanup(lambda: _safe_delete_glossary_term(ctx, term_id))

    # The term's attachment is indexed with a short delay; wait until it is visible so the
    # delete runs against a confirmed-attached term.
    _poll_until(
        lambda: {
            t["Id"] for t in glue.list_glossary_terms(GlossaryIdentifier=glossary_id).get("Items", [])
        },
        lambda ids: term_id in ids,
        timeout_s=60,
        interval_s=3,
    )

    glue.delete_glossary(Identifier=glossary_id)

    glossary_gone = _refusal(lambda: glue.get_glossary(Identifier=glossary_id))
    assert glossary_gone == ("EntityNotFoundException", f'{{"Message":"Business glossary {glossary_id} not found."}}'), glossary_gone

    # Orphaned, not cascade-deleted.
    orphaned_term = glue.get_glossary_term(Identifier=term_id)
    assert orphaned_term["Id"] == term_id, orphaned_term
    assert orphaned_term["GlossaryId"] == glossary_id, orphaned_term

    # Positive control: the orphaned term can still be deleted explicitly.
    glue.delete_glossary_term(Identifier=term_id)
    term_gone = _refusal(lambda: glue.get_glossary_term(Identifier=term_id))
    assert term_gone == ("EntityNotFoundException", f'{{"Message":"Business glossary term {term_id} not found."}}'), term_gone


# ===== helpers =====
def _refusal(fn):
    """Return the (code, message) of the ClientError fn raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while not predicate(value):
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout_s}s, last value={value!r}")
        time.sleep(interval_s)
        value = probe()
    return value


def _safe_delete_glossary_term(ctx, term_id):
    try:
        ctx.client("glue").delete_glossary_term(Identifier=term_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "EntityNotFoundException":
            raise


def _safe_delete_glossary(ctx, glossary_id):
    try:
        ctx.client("glue").delete_glossary(Identifier=glossary_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "EntityNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
