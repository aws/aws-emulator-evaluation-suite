"""account-color-cycle-through-all-enum-values."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "account-color-cycle-through-all-enum-values"
GROUP = "state"
SERVICES = ["uxc"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:uxc-account-customizations")
def run(ctx) -> None:
    """accountColor transitions correctly through every documented enum value and back to the default, one transition at a time."""
    uxc = ctx.client("uxc")
    snap = _snapshot(uxc)
    ctx.on_cleanup(lambda: _restore(uxc, snap))

    colors = [
        "pink", "purple", "darkBlue", "lightBlue", "teal",
        "green", "yellow", "orange", "red", "none",
    ]
    for color in colors:
        resp = uxc.update_account_customizations(accountColor=color)
        assert resp["accountColor"] == color, f"update response echoed {resp['accountColor']!r}, expected {color!r}"
        got = uxc.get_account_customizations()
        assert got["accountColor"] == color, f"expected transition to {color!r}, got {got['accountColor']!r}"


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
