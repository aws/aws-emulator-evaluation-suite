"""concurrent-delete-glossary-term-and-associate-both-succeed."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-delete-glossary-term-and-associate-both-succeed"
GROUP = "concurrency"
SERVICES = ["glue"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AssociateGlossaryTerms referencing a term, then DeleteGlossaryTerm on it: both succeed
    (the two operations are not cross-locked), the term then 404s with EntityNotFoundException,
    and the asset's association still names the deleted term id."""
    glue = ctx.client("glue")

    glossary_id = glue.create_glossary(Name=ctx.unique_name("sim2real-glossary-"))["Id"]
    ctx.on_cleanup(lambda: _safe(lambda: glue.delete_glossary(Identifier=glossary_id)))
    term_id = glue.create_glossary_term(
        GlossaryIdentifier=glossary_id, Name=ctx.unique_name("sim2real-term-")
    )["Id"]
    ctx.on_cleanup(lambda: _safe(lambda: glue.delete_glossary_term(Identifier=term_id)))

    asset_type_id, form_type_id, form_type_name = _make_asset_type(ctx, "DelTermRace")
    asset_id = ctx.unique_name("sim2real-asset-deltermrace-")
    glue.put_asset(AssetTypeId=asset_type_id, Identifier=asset_id, Name=asset_id, Forms={})
    ctx.on_cleanup(lambda: _safe(lambda: glue.delete_asset(Identifier=asset_id)))

    def _associate():
        return glue.associate_glossary_terms(AssetIdentifier=asset_id, GlossaryTermIdentifiers=[term_id])

    def _delete():
        return glue.delete_glossary_term(Identifier=term_id)

    # Sequenced, not raced: which call lands first in a true race is undocumented, and a delete
    # landing first makes the associate fail.
    results = _race([_associate]) + _race([_delete])
    associate_result, associate_code = results[0]
    _, delete_code = results[1]

    # Empirically, AssociateGlossaryTerms and DeleteGlossaryTerm are not cross-locked: both
    # succeed independently, with no ConcurrentModificationException.
    assert associate_code is None, f"expected AssociateGlossaryTerms to succeed, got code={associate_code}"
    assert associate_result["GlossaryTerms"] == [term_id], (
        f"expected AssociateGlossaryTerms response to list only {term_id}, "
        f"got {associate_result['GlossaryTerms']}"
    )
    assert delete_code is None, (
        f"expected DeleteGlossaryTerm to succeed independently (no cross-lock), got code={delete_code}"
    )

    # Effect: the term is gone even though the associate call referenced it.
    code, message = _error(lambda: glue.get_glossary_term(Identifier=term_id))
    assert code == "EntityNotFoundException", (
        f"expected the deleted term to 404 with EntityNotFoundException, got {code!r}"
    )
    assert message == f'{{"Message":"Business glossary term {term_id} not found."}}', message

    # Effect: the asset's association still names the (now-deleted) term id -- no retroactive
    # cleanup ties the two resources together.
    got_asset = glue.get_asset(Identifier=asset_id)
    assert got_asset.get("GlossaryTerms") == [term_id], got_asset


# ===== helpers =====
def _error(fn):
    """Call fn(); return its (code, message). An unexpected success raises: real AWS refuses it."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it succeeded and returned {result!r}")


def _safe(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "EntityNotFoundException":
            raise


def _race(fns):
    with ThreadPoolExecutor(max_workers=len(fns)) as pool:
        futures = [pool.submit(fn) for fn in fns]
        results = []
        for fut in futures:
            try:
                results.append((fut.result(), None))
            except ClientError as exc:
                results.append((None, exc.response.get("Error", {}).get("Code")))
    return results


def _word_name(ctx, prefix: str) -> str:
    suffix = "".join(ch for ch in ctx.unique_name("x") if ch.isalnum())
    return prefix + suffix


def _make_asset_type(ctx, tag: str):
    glue = ctx.client("glue")
    form_type_name = _word_name(ctx, f"Sim2Real{tag}Form")
    form_type_id = glue.put_form_type(
        Name=form_type_name, Schema=f"structure {form_type_name} {{ note: String }}"
    )["Id"]
    ctx.on_cleanup(lambda: _safe(lambda: glue.delete_form_type(Identifier=form_type_id)))

    asset_type_name = _word_name(ctx, f"sim2real{tag}AssetType")
    asset_type_id = glue.put_asset_type(
        Name=asset_type_name, Forms={form_type_name: {"FormTypeIdentifier": form_type_id}}
    )["Id"]
    ctx.on_cleanup(lambda: _safe(lambda: glue.delete_asset_type(Identifier=asset_type_id)))
    return asset_type_id, form_type_id, form_type_name


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
