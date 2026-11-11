"""visible-services-empty-list-distinct-from-configured-list."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "visible-services-empty-list-distinct-from-configured-list"
GROUP = "state"
SERVICES = ["uxc"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:uxc-account-customizations")
def run(ctx) -> None:
    """An explicit empty visibleServices list ([]) persists as zero visible services, distinct from the prior non-empty list."""
    uxc = ctx.client("uxc")
    snap = _snapshot(uxc)
    ctx.on_cleanup(lambda: _restore(uxc, snap))

    resp = uxc.update_account_customizations(visibleServices=["s3", "ec2", "lambda"])
    assert sorted(resp["visibleServices"]) == ["ec2", "lambda", "s3"], (
        f"expected update response visibleServices=[ec2, lambda, s3], got {resp['visibleServices']!r}"
    )

    configured = uxc.get_account_customizations()
    assert sorted(configured["visibleServices"]) == ["ec2", "lambda", "s3"], (
        "expected independent read to reflect the just-configured non-empty list "
        f"[ec2, lambda, s3], got {configured['visibleServices']!r}"
    )

    resp = uxc.update_account_customizations(visibleServices=[])
    assert resp["visibleServices"] == [], (
        f"expected update response visibleServices=[], got {resp['visibleServices']!r}"
    )

    got = uxc.get_account_customizations()
    assert got["visibleServices"] == [], (
        f"expected independent read after clearing to be empty, got {got['visibleServices']!r}"
    )
    assert "s3" not in got["visibleServices"], (
        f"expected 's3' absent from cleared visibleServices, got {got['visibleServices']!r}"
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
