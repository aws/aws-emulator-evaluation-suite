"""account-color-reset-to-none-after-being-set."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "account-color-reset-to-none-after-being-set"
GROUP = "state"
SERVICES = ["uxc"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:uxc-account-customizations")
def run(ctx) -> None:
    """Setting accountColor explicitly to 'none' resets the preference to its default."""
    uxc = ctx.client("uxc")
    snap = _snapshot(uxc)
    ctx.on_cleanup(lambda: _restore(uxc, snap))

    resp = uxc.update_account_customizations(accountColor="orange")
    assert resp["accountColor"] == "orange", (
        f"expected update response accountColor 'orange', got {resp['accountColor']!r}"
    )
    got = uxc.get_account_customizations()["accountColor"]
    assert got == "orange", f"expected persisted accountColor 'orange', got {got!r}"

    resp = uxc.update_account_customizations(accountColor="none")
    assert resp["accountColor"] == "none", (
        f"expected update response accountColor 'none' after explicit reset, got {resp['accountColor']!r}"
    )
    got = uxc.get_account_customizations()["accountColor"]
    assert got == "none", f"expected persisted accountColor 'none' after explicit reset, got {got!r}"


def _snapshot(uxc):
    resp = uxc.get_account_customizations()
    return {
        "accountColor": resp.get("accountColor", "none"),
        "visibleServices": resp.get("visibleServices"),
        "visibleRegions": resp.get("visibleRegions"),
    }


def _restore(uxc, snap):
    kwargs = {"accountColor": snap["accountColor"] or "none"}
    if snap["visibleServices"] is not None:
        kwargs["visibleServices"] = snap["visibleServices"]
    if snap["visibleRegions"] is not None:
        kwargs["visibleRegions"] = snap["visibleRegions"]
    uxc.update_account_customizations(**kwargs)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
