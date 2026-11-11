"""update-idempotent-repeated-identical-call."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "update-idempotent-repeated-identical-call"
GROUP = "state"
SERVICES = ["uxc"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:uxc-account-customizations")
def run(ctx) -> None:
    """Issuing the same UpdateAccountCustomizations request twice in a row is idempotent."""
    uxc = ctx.client("uxc")
    snap = _snapshot(uxc)
    ctx.on_cleanup(lambda: _restore(uxc, snap))

    params = {"accountColor": "lightBlue", "visibleServices": ["s3", "dynamodb"]}
    first = uxc.update_account_customizations(**params)
    second = uxc.update_account_customizations(**params)

    assert first["accountColor"] == second["accountColor"] == "lightBlue", (
        f"repeated identical UpdateAccountCustomizations must return the same accountColor "
        f"both times: first={first['accountColor']!r} second={second['accountColor']!r}"
    )
    assert sorted(first["visibleServices"]) == sorted(second["visibleServices"]) == ["dynamodb", "s3"], (
        "repeated identical UpdateAccountCustomizations must not duplicate or drop entries on "
        f"replace: first={sorted(first['visibleServices'])!r} second={sorted(second['visibleServices'])!r}"
    )

    got = uxc.get_account_customizations()
    assert got["accountColor"] == "lightBlue", (
        f"GetAccountCustomizations after two identical updates expected accountColor='lightBlue', "
        f"got {got['accountColor']!r}"
    )
    assert sorted(got["visibleServices"]) == ["dynamodb", "s3"], (
        f"GetAccountCustomizations after two identical updates expected visibleServices=['dynamodb', 's3'], "
        f"got {sorted(got['visibleServices'])!r}"
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
