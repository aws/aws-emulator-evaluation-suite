"""update-multiple-fields-single-call-all-persisted."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "update-multiple-fields-single-call-all-persisted"
GROUP = "state"
SERVICES = ["uxc"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:uxc-account-customizations")
def run(ctx) -> None:
    """A single UpdateAccountCustomizations call setting all three fields commits them atomically together."""
    uxc = ctx.client("uxc")
    snap = _snapshot(uxc)
    ctx.on_cleanup(lambda: _restore(uxc, snap))

    resp = uxc.update_account_customizations(
        accountColor="teal",
        visibleServices=["s3", "ec2", "lambda"],
        visibleRegions=["us-east-1", "us-west-2"],
    )
    assert resp["accountColor"] == "teal", (
        f"expected accountColor='teal' in update response, got {resp['accountColor']!r}"
    )
    assert sorted(resp["visibleServices"]) == ["ec2", "lambda", "s3"], (
        f"expected visibleServices=['ec2','lambda','s3'] in update response, "
        f"got {sorted(resp['visibleServices'])!r}"
    )
    assert sorted(resp["visibleRegions"]) == ["us-east-1", "us-west-2"], (
        f"expected visibleRegions=['us-east-1','us-west-2'] in update response, "
        f"got {sorted(resp['visibleRegions'])!r}"
    )

    # The response is authoritative: an immediate Get must match it exactly, all three fields together.
    got = uxc.get_account_customizations()
    assert got["accountColor"] == resp["accountColor"], (
        f"expected persisted accountColor={resp['accountColor']!r}, got {got['accountColor']!r}"
    )
    assert sorted(got["visibleServices"]) == sorted(resp["visibleServices"]), (
        f"expected persisted visibleServices={sorted(resp['visibleServices'])!r}, "
        f"got {sorted(got['visibleServices'])!r}"
    )
    assert sorted(got["visibleRegions"]) == sorted(resp["visibleRegions"]), (
        f"expected persisted visibleRegions={sorted(resp['visibleRegions'])!r}, "
        f"got {sorted(got['visibleRegions'])!r}"
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
