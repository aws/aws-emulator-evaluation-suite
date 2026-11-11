"""concurrent-asset-type-put-both-succeed."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-asset-type-put-both-succeed"
GROUP = "concurrency"
SERVICES = ["glue"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Two simultaneous PutAssetType upserts of one asset type are each accepted or refused with
    ConcurrentModificationException; GetAssetType then holds exactly one winner's Forms (never a merge), or the
    pre-race Forms if both were refused, and a further sequential PutAssetType replaces them."""
    glue = ctx.client("glue")

    form_a_name = _word_name(ctx, "Sim2RealTypeRaceFormA")
    form_a_id = glue.put_form_type(Name=form_a_name, Schema=f"structure {form_a_name} {{ a: String }}")["Id"]
    ctx.on_cleanup(lambda: _safe(lambda: glue.delete_form_type(Identifier=form_a_id)))
    form_b_name = _word_name(ctx, "Sim2RealTypeRaceFormB")
    form_b_id = glue.put_form_type(Name=form_b_name, Schema=f"structure {form_b_name} {{ b: String }}")["Id"]
    ctx.on_cleanup(lambda: _safe(lambda: glue.delete_form_type(Identifier=form_b_id)))

    asset_type_name = _word_name(ctx, "sim2realTypeRaceAssetType")
    asset_type_id = glue.put_asset_type(
        Name=asset_type_name, Forms={form_a_name: {"FormTypeIdentifier": form_a_id}}
    )["Id"]
    ctx.on_cleanup(lambda: _safe(lambda: glue.delete_asset_type(Identifier=asset_type_id)))

    def _put(form_name, form_id):
        return glue.put_asset_type(Name=asset_type_name, Forms={form_name: {"FormTypeIdentifier": form_id}})

    results = _race([lambda: _put(form_a_name, form_a_id), lambda: _put(form_b_name, form_b_id)])
    successes = [r for r, c in results if c is None]
    failures = [c for _, c in results if c is not None]

    # A rejected racer always gets the optimistic-lock conflict code, never another error, whether zero, one or
    # both racers are rejected.
    for code in failures:
        assert code == "ConcurrentModificationException", (
            f"expected the only possible PutAssetType race rejection to be "
            f"ConcurrentModificationException, got {code!r} (results={results})"
        )
    winner_forms_candidates = [set(r["Forms"].keys()) for r in successes]
    for wf in winner_forms_candidates:
        assert wf in ({form_a_name}, {form_b_name}), wf

    # Effect: GetAssetType settles on exactly one racer's Forms in full if either succeeded --
    # never a merge of both -- or is left at its pre-race value if both racers were rejected.
    got = glue.get_asset_type(Identifier=asset_type_id)
    final_forms = set(got["Forms"].keys())
    if successes:
        assert final_forms in ({form_a_name}, {form_b_name}), final_forms
    else:
        assert final_forms == {form_a_name}, (
            f"both racers were rejected, but Forms changed to {final_forms} anyway"
        )

    # Positive control: with no concurrent writer, PutAssetType succeeds normally.
    control_name = _word_name(ctx, "Sim2RealTypeRaceFormC")
    control_id = glue.put_form_type(Name=control_name, Schema=f"structure {control_name} {{ c: String }}")["Id"]
    ctx.on_cleanup(lambda: _safe(lambda: glue.delete_form_type(Identifier=control_id)))
    glue.put_asset_type(Name=asset_type_name, Forms={control_name: {"FormTypeIdentifier": control_id}})
    final_control_forms = set(glue.get_asset_type(Identifier=asset_type_id)["Forms"].keys())
    assert final_control_forms == {control_name}, (
        f"expected sequential PutAssetType (no concurrent writer) to leave Forms={control_name!r}, "
        f"got {final_control_forms}"
    )


# ===== helpers =====
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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
