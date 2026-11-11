"""concurrent-delete-asset-conflict-rejected."""
from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-delete-asset-conflict-rejected"
GROUP = "concurrency"
SERVICES = ["glue"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Racing DeleteAsset against PutAsset on one asset: any refusal is ConcurrentModificationException, and
    the asset's own state (not DeleteAsset's 200) ends gone, untouched, or holding exactly PutAsset's
    write, never a hybrid; a sequential call afterwards succeeds."""
    glue = ctx.client("glue")

    asset_type_id, form_type_id, form_type_name = _make_asset_type(ctx, "DelAssetRace")
    asset_id = ctx.unique_name("sim2real-asset-delassetrace-")
    glue.put_asset(
        AssetTypeId=asset_type_id, Identifier=asset_id, Name=asset_id,
        Description="initial-description", Forms={},
    )
    ctx.on_cleanup(lambda: _safe(lambda: glue.delete_asset(Identifier=asset_id)))

    def _put():
        return glue.put_asset(
            AssetTypeId=asset_type_id, Identifier=asset_id, Name=asset_id,
            Description="updated-by-racing-put", Forms={},
        )

    def _delete():
        return glue.delete_asset(Identifier=asset_id)

    results = _race([_put, _delete])
    _, put_error = results[0]
    _, delete_error = results[1]
    for error, label in ((put_error, "PutAsset"), (delete_error, "DeleteAsset")):
        if error is not None:
            assert error == ("ConcurrentModificationException", "{}"), (
                f"expected the rejected racer ({label}) to fail with ConcurrentModificationException, got {error}"
            )
    not_found = f'{{"Message":"Asset not found: {asset_id}"}}'

    def _recreate_control():
        # Positive control: with no concurrent writer now, a plain PutAsset succeeds normally.
        glue.put_asset(
            AssetTypeId=asset_type_id, Identifier=asset_id, Name=asset_id,
            Description="post-race-control", Forms={},
        )
        got_control = glue.get_asset(Identifier=asset_id)["Description"]
        assert got_control == "post-race-control", got_control

    def _delete_control():
        # Positive control: with no concurrent writer, the delete now succeeds for real.
        glue.delete_asset(Identifier=asset_id)
        assert _settles_gone(lambda: glue.get_asset(Identifier=asset_id), not_found), (
            "the sequential DeleteAsset reported success but the asset is still readable"
        )

    if put_error is not None and delete_error is not None:
        # Both racers were genuinely rejected client-side: neither write was ever attempted,
        # so the asset must still hold its untouched pre-race content.
        got = glue.get_asset(Identifier=asset_id)["Description"]
        assert got == "initial-description", got
        _recreate_control()
    elif delete_error is not None:
        # PutAsset succeeded for real (its 200 response echoes the applied state), DeleteAsset
        # was rejected client-side: the racing write is visible.
        got = glue.get_asset(Identifier=asset_id)["Description"]
        assert got == "updated-by-racing-put", got
        _delete_control()
    else:
        # DeleteAsset reported success. That alone does not mean it took effect (see
        # docstring) -- only the resource's own state after a bounded settle window says
        # which. PutAsset's write can be visible only if PutAsset itself did not raise.
        if _settles_gone(lambda: glue.get_asset(Identifier=asset_id), not_found):
            _recreate_control()
        else:
            got = glue.get_asset(Identifier=asset_id)["Description"]
            expected = "updated-by-racing-put" if put_error is None else "initial-description"
            assert got == expected, (
                f"asset survived DeleteAsset's reported success with an unexpected "
                f"Description (expected {expected!r}, got {got!r})"
            )


# ===== helpers =====
def _settles_gone(fn, not_found_message: str, timeout_s: float = 20.0, interval_s: float = 1.0) -> bool:
    """Poll a read until it raises EntityNotFoundException with AWS's exact message (True), or the
    timeout passes while the read keeps succeeding (False); any other error fails the check.
    Bounded retry, not a sleep: a genuine delete resolves in well under a second (measured
    against real AWS); a DeleteAsset that reported success but did not take effect never
    resolves even after 30s (measured against real AWS), so 20s cleanly separates the two."""
    deadline = time.time() + timeout_s
    while True:
        try:
            fn()
        except ClientError as err:
            error = (err.response["Error"]["Code"], err.response["Error"].get("Message"))
            assert error == ("EntityNotFoundException", not_found_message), error
            return True
        if time.time() >= deadline:
            return False
        time.sleep(interval_s)


def _safe(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "EntityNotFoundException":
            raise


def _race(fns):
    barrier = threading.Barrier(len(fns))

    def _synced(fn):
        barrier.wait()
        return fn()

    with ThreadPoolExecutor(max_workers=len(fns)) as pool:
        futures = [pool.submit(_synced, fn) for fn in fns]
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
