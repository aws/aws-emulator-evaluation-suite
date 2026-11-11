"""concurrent-asset-put-conflict-rejected."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-asset-put-conflict-rejected"
GROUP = "concurrency"
SERVICES = ["glue"]
_CME_MESSAGE = "{}"


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Two simultaneous PutAsset upserts of one existing asset with different Descriptions: each
    is applied or refused with ConcurrentModificationException, GetAsset then shows an applied
    call's Description (or the original if none applied), and a later uncontended put succeeds."""
    glue = ctx.client("glue")

    asset_type_id, form_type_id, form_type_name = _make_asset_type(ctx, "PutRace")
    asset_id = ctx.unique_name("sim2real-asset-putrace-")
    glue.put_asset(
        AssetTypeId=asset_type_id, Identifier=asset_id, Name=asset_id,
        Description="initial-description", Forms={},
    )
    ctx.on_cleanup(lambda: _safe(lambda: glue.delete_asset(Identifier=asset_id)))

    def _put(desc):
        return glue.put_asset(
            AssetTypeId=asset_type_id, Identifier=asset_id, Name=asset_id, Description=desc, Forms={}
        )

    descs = ("racer-a-description", "racer-b-description")
    results = _race([lambda d=d: _put(d) for d in descs])
    applied = {d for d, (_, err) in zip(descs, results) if err is None}
    for d, (resp, err) in zip(descs, results):
        if err is None:
            assert resp["Description"] == d, f"PutAsset echoed a Description it was not sent: {resp!r}"
            continue
        code, message = err
        assert code == "ConcurrentModificationException", f"undocumented PutAsset refusal: {code!r} ({message!r})"
        assert message == _CME_MESSAGE, (
            f"ConcurrentModificationException message {message!r}, expected {_CME_MESSAGE!r}"
        )

    got = glue.get_asset(Identifier=asset_id)
    assert got["Description"] in (applied or {"initial-description"}), (got, applied, results)

    # Positive control: with no concurrent writer, PutAsset succeeds normally. Use a fresh
    # Identifier rather than continuing to fight over the raced one, which can stay in a
    # contended state for a while after two racers just collided on it.
    control_asset_id = ctx.unique_name("sim2real-asset-putrace-control-")
    glue.put_asset(
        AssetTypeId=asset_type_id, Identifier=control_asset_id, Name=control_asset_id,
        Description="post-race-control", Forms={},
    )
    ctx.on_cleanup(lambda: _safe(lambda: glue.delete_asset(Identifier=control_asset_id)))
    control_got = glue.get_asset(Identifier=control_asset_id)
    assert control_got["Description"] == "post-race-control", (
        f"expected the uncontended control write to land, got {control_got['Description']!r}"
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
