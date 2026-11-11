"""concurrent-glossary-term-association-conflict-rejected."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-glossary-term-association-conflict-rejected"
GROUP = "concurrency"
SERVICES = ["glue"]
_CME_MESSAGE = "{}"


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Two concurrent AssociateGlossaryTerms calls for one (asset, term) pair: each is applied or
    refused with ConcurrentModificationException, the asset then carries the term exactly once if
    any call applied (else only the baseline term), and a sequential repeat is idempotent."""
    glue = ctx.client("glue")

    glossary_id = glue.create_glossary(Name=ctx.unique_name("sim2real-glossary-"))["Id"]
    ctx.on_cleanup(lambda: _safe(lambda: glue.delete_glossary(Identifier=glossary_id)))
    term_id = glue.create_glossary_term(
        GlossaryIdentifier=glossary_id, Name=ctx.unique_name("sim2real-term-")
    )["Id"]
    ctx.on_cleanup(lambda: _safe(lambda: glue.delete_glossary_term(Identifier=term_id)))

    asset_type_id, form_type_id, form_type_name = _make_asset_type(ctx, "AssocRace")
    asset_id = ctx.unique_name("sim2real-asset-assocrace-")
    glue.put_asset(AssetTypeId=asset_type_id, Identifier=asset_id, Name=asset_id, Forms={})
    ctx.on_cleanup(lambda: _safe(lambda: glue.delete_asset(Identifier=asset_id)))

    # Positive control: a single non-racing AssociateGlossaryTerms against this asset
    # succeeds, so a rejection below is attributable to the race, not to a broken target.
    baseline_term_id = glue.create_glossary_term(
        GlossaryIdentifier=glossary_id, Name=ctx.unique_name("sim2real-baseline-term-")
    )["Id"]
    ctx.on_cleanup(lambda: _safe(lambda: glue.delete_glossary_term(Identifier=baseline_term_id)))
    baseline = glue.associate_glossary_terms(
        AssetIdentifier=asset_id, GlossaryTermIdentifiers=[baseline_term_id]
    )
    assert baseline["GlossaryTerms"] == [baseline_term_id], (
        f"expected baseline association to succeed with [{baseline_term_id}], got {baseline}"
    )

    def _associate():
        return glue.associate_glossary_terms(AssetIdentifier=asset_id, GlossaryTermIdentifiers=[term_id])

    results = _race([_associate, _associate])
    successes = [r for r, c in results if c is None]
    for resp, err in results:
        if err is None:
            assert set(resp["GlossaryTerms"]) == {baseline_term_id, term_id}, (
                f"an applied racer did not report {{{baseline_term_id}, {term_id}}}: {resp}"
            )
            continue
        code, message = err
        assert code == "ConcurrentModificationException", (
            f"undocumented AssociateGlossaryTerms refusal: {code!r} ({message!r})"
        )
        assert message == _CME_MESSAGE, (
            f"ConcurrentModificationException message {message!r}, expected {_CME_MESSAGE!r}"
        )

    # Effect: the term is associated once if any racer applied, and not at all otherwise.
    expected = {baseline_term_id, term_id} if successes else {baseline_term_id}
    got = glue.get_asset(Identifier=asset_id)
    assert set(got.get("GlossaryTerms", [])) == expected, got
    assert len(got.get("GlossaryTerms", [])) == len(expected), f"a glossary term is associated twice: {got}"

    # Positive control: with no concurrent writer, the same association call is idempotent.
    repeat = glue.associate_glossary_terms(AssetIdentifier=asset_id, GlossaryTermIdentifiers=[term_id])
    assert set(repeat["GlossaryTerms"]) == {baseline_term_id, term_id}, repeat


# ===== helpers =====
def _safe(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "EntityNotFoundException":
            raise


def _race(fns):
    """Fire callables concurrently; return [(result, (code, message) or None), ...] in input order."""
    with ThreadPoolExecutor(max_workers=len(fns)) as pool:
        futures = [pool.submit(fn) for fn in fns]
        results = []
        for fut in futures:
            try:
                results.append((fut.result(), None))
            except ClientError as exc:
                err = exc.response.get("Error", {})
                results.append((None, (err.get("Code"), err.get("Message"))))
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
