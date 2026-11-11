"""list-services-values-usable-in-update-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-services-values-usable-in-update-round-trip"
GROUP = "state"
SERVICES = ["uxc"]


@tags("axis:happy-path", "cap:c1", "cap:c5", "concern:representation", "plane:control", "resource:account-singleton:uxc-account-customizations")
def run(ctx) -> None:
    """Service identifiers returned by ListServices are valid values for UpdateAccountCustomizations.visibleServices."""
    uxc = ctx.client("uxc")
    snap = _snapshot(uxc)
    ctx.on_cleanup(lambda: _restore(uxc, snap))

    page = uxc.list_services(maxResults=5)
    services = page["services"]
    assert len(services) >= 1, "ListServices returned no service identifiers to exercise"
    chosen = services[:3] if len(services) >= 3 else services

    resp = uxc.update_account_customizations(visibleServices=chosen)
    assert sorted(resp["visibleServices"]) == sorted(chosen), (
        f"expected update response visibleServices={sorted(chosen)!r}, got {resp['visibleServices']!r}"
    )

    got = uxc.get_account_customizations()
    assert sorted(got["visibleServices"]) == sorted(chosen), (
        f"expected independent read visibleServices={sorted(chosen)!r}, got {got['visibleServices']!r}"
    )


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
