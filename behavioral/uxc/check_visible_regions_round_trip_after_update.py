"""visible-regions-round-trip-after-update."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "visible-regions-round-trip-after-update"
GROUP = "state"
SERVICES = ["uxc"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:uxc-account-customizations")
def run(ctx) -> None:
    """UpdateAccountCustomizations persists visibleRegions and GetAccountCustomizations reflects the exact set."""
    uxc = ctx.client("uxc")
    snap = _snapshot(uxc)
    ctx.on_cleanup(lambda: _restore(uxc, snap))

    resp = uxc.update_account_customizations(visibleRegions=["us-east-1", "eu-west-1", "ap-northeast-1"])
    assert sorted(resp["visibleRegions"]) == ["ap-northeast-1", "eu-west-1", "us-east-1"], (
        f"expected visibleRegions=['ap-northeast-1', 'eu-west-1', 'us-east-1'] in update "
        f"response, got {sorted(resp.get('visibleRegions', []))!r}"
    )

    got = uxc.get_account_customizations()
    assert sorted(got["visibleRegions"]) == ["ap-northeast-1", "eu-west-1", "us-east-1"], (
        f"expected visibleRegions=['ap-northeast-1', 'eu-west-1', 'us-east-1'] on independent "
        f"read, got {sorted(got.get('visibleRegions', []))!r}"
    )
    # PATCH semantics: this call only named visibleRegions, so accountColor must survive
    # unchanged — a target that resets it (rather than genuinely preserving it) is the
    # defect this assertion exists to catch. `is not None` would pass either way.
    assert got["accountColor"] == snap["accountColor"], (
        f"partial update of visibleRegions must not alter accountColor; expected "
        f"{snap['accountColor']!r} (pre-update value), got {got['accountColor']!r}"
    )


def _snapshot(uxc):
    resp = uxc.get_account_customizations()
    return {
        "accountColor": resp.get("accountColor", "none"),
        "visibleServices": resp.get("visibleServices"),
        "visibleRegions": resp.get("visibleRegions"),
    }


def _restore(uxc, snap):
    """Write back the snapshot exactly. A never-configured list reads as null and is reset by
    sending an explicit JSON null, which botocore's serializer drops, so the body is patched."""
    kwargs = {"accountColor": snap["accountColor"] or "none"}
    nulls = [k for k in ("visibleServices", "visibleRegions") if snap[k] is None]
    for k in ("visibleServices", "visibleRegions"):
        if snap[k] is not None:
            kwargs[k] = snap[k]

    def send_nulls(request, **_):
        body = json.loads(request.body or b"{}")
        body.update({k: None for k in nulls})
        request.data = json.dumps(body).encode()
        request.headers["Content-Length"] = str(len(request.data))

    event = "before-sign.uxc.UpdateAccountCustomizations"
    uxc.meta.events.register(event, send_nulls, unique_id="sim2real-uxc-restore-nulls")
    try:
        uxc.update_account_customizations(**kwargs)
    finally:
        uxc.meta.events.unregister(event, unique_id="sim2real-uxc-restore-nulls")
    restored = _snapshot(uxc)
    assert restored == snap, f"restore left the account customizations at {restored!r}, not {snap!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
