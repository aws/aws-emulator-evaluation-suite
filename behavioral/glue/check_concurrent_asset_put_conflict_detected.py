"""concurrent-asset-put-conflict-detected."""
from __future__ import annotations

import json
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-asset-put-conflict-detected"
GROUP = "concurrency"
SERVICES = ["glue"]
_CME_MESSAGE = "{}"


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Two simultaneous PutAsset updates of one existing asset: each is applied or refused with
    ConcurrentModificationException (both may be refused), and GetAsset then shows the Name of an
    applied call, or the original Name if none applied, never a refused call's write."""
    glue = ctx.client("glue")

    form_type_id = _create_form_type(ctx)
    asset_type_id = _create_asset_type(ctx, form_type_id)
    identifier = ctx.unique_name("sim2real-asset-")
    glue.put_asset(
        AssetTypeId=asset_type_id,
        Identifier=identifier,
        Name="initial-name",
        Forms={"Note": {"FormTypeId": form_type_id, "Content": json.dumps({"note": "init"})}},
    )
    ctx.on_cleanup(lambda: _safe_call(lambda: glue.delete_asset(Identifier=identifier)))

    # let the just-created asset settle (bounded poll, not a bare sleep) before racing writers
    # against it - a write immediately following creation can otherwise be seen as colliding
    # with the creation itself rather than with the other racers we actually want to test.
    _poll_until(lambda: glue.get_asset(Identifier=identifier)["Name"] == "initial-name", timeout=_wait_s(ctx, 20))

    def make_call(tag: str):
        def _call():
            return glue.put_asset(
                AssetTypeId=asset_type_id,
                Identifier=identifier,
                Name=f"race-{tag}",
                Forms={
                    "Note": {
                        "FormTypeId": form_type_id,
                        "Content": json.dumps({"note": tag}),
                    }
                },
            )

        return _call

    # two simultaneous updaters, per the plan.
    racers = 2
    tags = [f"r{i}" for i in range(racers)]
    outcomes = _race([make_call(t) for t in tags])

    applied = {f"race-{t}" for t, o in zip(tags, outcomes) if o["error"] is None}
    for t, o in zip(tags, outcomes):
        if o["error"] is None:
            assert o["result"]["Name"] == f"race-{t}", f"PutAsset echoed a Name it was not sent: {o}"
            continue
        code, message = o["error"]
        assert code == "ConcurrentModificationException", f"undocumented PutAsset refusal: {code!r} ({message!r})"
        assert message == _CME_MESSAGE, (
            f"ConcurrentModificationException message {message!r}, expected {_CME_MESSAGE!r}"
        )

    expected_names = applied or {"initial-name"}
    final_name = glue.get_asset(Identifier=identifier)["Name"]
    assert final_name in expected_names, (final_name, expected_names, outcomes)


# ===== helpers =====

def _sanitize(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9]", "", s)


def _safe_call(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "EntityNotFoundException":
            raise


def _create_form_type(ctx) -> str:
    glue = ctx.client("glue")
    name = "SimForm" + _sanitize(ctx.unique_name("x"))[-12:]
    glue.put_form_type(Name=name, Schema=f"structure {name} {{\n    note: String\n}}")
    ctx.on_cleanup(lambda: _safe_call(lambda: glue.delete_form_type(Identifier=name)))
    return name


def _create_asset_type(ctx, form_type_id: str) -> str:
    glue = ctx.client("glue")
    name = "SimType" + _sanitize(ctx.unique_name("x"))[-12:]
    glue.put_asset_type(Name=name, Forms={"Note": {"FormTypeIdentifier": form_type_id}})
    ctx.on_cleanup(lambda: _safe_call(lambda: glue.delete_asset_type(Identifier=name)))
    return name


def _wait_s(ctx, cap_s):
    """cap_s, shortened so the wait ends before the runner's budget does."""
    left = ctx.time_left()
    if left is None:
        return cap_s
    return max(1.0, min(cap_s, left - 10.0))


def _poll_until(predicate, timeout=20.0, interval=1.0) -> None:
    """Bounded poll for an async/eventually-consistent condition; never a bare sleep."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            if predicate():
                return
        except ClientError:
            pass
        time.sleep(interval)
    # last attempt: raise on timeout rather than silently returning a false result
    assert predicate(), "timed out waiting for the just-created asset to settle"


def _race(calls: list) -> list:
    n = len(calls)
    barrier = threading.Barrier(n)
    outcomes: list = [None] * n

    def worker(i: int, fn) -> None:
        barrier.wait()
        try:
            outcomes[i] = {"result": fn(), "error": None}
        except ClientError as e:
            outcomes[i] = {"result": None, "error": (e.response["Error"]["Code"], e.response["Error"].get("Message"))}

    with ThreadPoolExecutor(max_workers=n) as pool:
        futures = [pool.submit(worker, i, fn) for i, fn in enumerate(calls)]
        for f in futures:
            f.result()
    return outcomes


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
