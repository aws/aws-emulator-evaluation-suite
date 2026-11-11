"""put-asset-concurrent-update-optimistic-lock-rejected."""
from __future__ import annotations

import re
import time
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-asset-concurrent-update-optimistic-lock-rejected"
GROUP = "concurrency"
SERVICES = ["glue"]
_CME_MESSAGE = "{}"


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Two concurrent PutAsset updates (Name v1 and v2) of one existing asset: each is applied or
    refused with ConcurrentModificationException, and GetAsset then shows an applied call's Name,
    or v0 if none applied, never a refused call's write."""
    glue = ctx.client("glue")

    form_type_name = "SimReal" + _word(ctx.unique_name("form"))
    schema = f"structure {form_type_name} {{\n    tag: String\n}}"
    form_type_id = _retry_on_concurrent_mod(
        glue.put_form_type, timeout_s=_wait_s(ctx, 90), Name=form_type_name, Schema=schema
    )["Id"]
    ctx.on_cleanup(lambda: _ignore(lambda: glue.delete_form_type(Identifier=form_type_id)))

    asset_type_name = "SimRealAssetType" + _word(ctx.unique_name("assettype"))
    asset_type_id = _retry_on_concurrent_mod(
        glue.put_asset_type,
        timeout_s=_wait_s(ctx, 90),
        Name=asset_type_name,
        Forms={form_type_name: {"FormTypeIdentifier": form_type_id}},
    )["Id"]
    ctx.on_cleanup(lambda: _ignore(lambda: glue.delete_asset_type(Identifier=asset_type_id)))

    asset_id = ctx.unique_name("sim2real-glue-asset-")
    _retry_on_concurrent_mod(
        glue.put_asset, timeout_s=_wait_s(ctx, 90), AssetTypeId=asset_type_id, Identifier=asset_id, Name="v0", Forms={}
    )
    ctx.on_cleanup(lambda: _ignore(lambda: glue.delete_asset(Identifier=asset_id)))

    with ThreadPoolExecutor(max_workers=2) as pool:
        f1 = pool.submit(
            glue.put_asset, AssetTypeId=asset_type_id, Identifier=asset_id, Name="v1", Forms={}
        )
        f2 = pool.submit(
            glue.put_asset, AssetTypeId=asset_type_id, Identifier=asset_id, Name="v2", Forms={}
        )
        outcomes = []
        for fut, label in ((f1, "v1"), (f2, "v2")):
            try:
                fut.result()
                outcomes.append(("success", label))
            except ClientError as e:
                outcomes.append(((e.response["Error"]["Code"], e.response["Error"].get("Message")), label))

    successes = [o for o in outcomes if o[0] == "success"]
    failures = [o for o in outcomes if o[0] != "success"]
    assert len(successes) + len(failures) == 2, (
        f"expected exactly 2 outcomes for 2 racers, got {outcomes}"
    )
    for (code, message), label in failures:
        assert code == "ConcurrentModificationException", (
            f"undocumented PutAsset refusal for {label}: {code!r} ({message!r}) (outcomes={outcomes})"
        )
        assert message == _CME_MESSAGE, (
            f"ConcurrentModificationException message {message!r}, expected {_CME_MESSAGE!r}"
        )

    # The asset reflects one applied write in full, or its pre-race value if both were refused.
    current = glue.get_asset(Identifier=asset_id)
    succeeded_labels = {label for _, label in successes}
    assert current["Name"] in (succeeded_labels or {"v0"}), (
        f"final Name {current['Name']!r} is not an applied write {sorted(succeeded_labels)} "
        f"(or v0 when none applied): {outcomes}"
    )

    # Positive control: a plain sequential PutAsset (no concurrent writer) still succeeds -- proving
    # the account/credentials/AssetTypeId are otherwise healthy for this operation. The
    # just-raced identifier itself can keep rejecting writes with
    # ConcurrentModificationException for well over 200s straight -- far past any "transient
    # settling" window -- so the control targets a FRESH Identifier rather than fighting over the
    # raced one.
    control_asset_id = ctx.unique_name("sim2real-glue-asset-control-")
    _retry_on_concurrent_mod(
        glue.put_asset, timeout_s=_wait_s(ctx, 90), AssetTypeId=asset_type_id, Identifier=control_asset_id, Name="v3", Forms={}
    )
    ctx.on_cleanup(lambda: _ignore(lambda: glue.delete_asset(Identifier=control_asset_id)))
    after = glue.get_asset(Identifier=control_asset_id)
    assert after["Name"] == "v3", f"expected the fresh-identifier control write to land, got {after['Name']!r}"


# ===== helpers =====
def _word(raw: str) -> str:
    return re.sub(r"[^A-Za-z0-9]", "", raw)


def _wait_s(ctx, cap_s):
    """cap_s, shortened so the wait ends before the runner's budget does."""
    left = ctx.time_left()
    if left is None:
        return cap_s
    return max(1.0, min(cap_s, left - 10.0))


def _retry_on_concurrent_mod(fn, timeout_s: float = 90.0, **kwargs):
    """Business-context catalog metadata (form types, asset types, assets) can be
    contended by other, unrelated concurrent activity in the account; retry the
    transient ConcurrentModificationException on setup/control calls that are not
    themselves the race under test. If it never clears within the budget, this account's
    current state makes the setup path for this check unreachable right now rather than a
    bug in the check itself."""
    deadline = time.time() + timeout_s
    last_error = None
    while time.time() < deadline:
        try:
            return fn(**kwargs)
        except ClientError as e:
            if e.response["Error"]["Code"] == "ConcurrentModificationException":
                last_error = e
                time.sleep(5)
                continue
            raise
    raise AssertionError(
        "PutAsset/PutAssetType/PutFormType setup kept raising ConcurrentModificationException "
        f"for {timeout_s:.0f}s straight in this account, well beyond a transient collision "
        f"window -- cannot reach the setup state needed to exercise the race: {last_error}"
    )


def _ignore(fn) -> None:
    """Teardown delete: an already-gone entity is done; a contended one is retried, else raise."""
    deadline = time.monotonic() + 60.0
    while True:
        try:
            fn()
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "EntityNotFoundException":
                return
            if code != "ConcurrentModificationException" or time.monotonic() >= deadline:
                raise
        time.sleep(2)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
