"""partial-update-preserves-unspecified-fields."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "partial-update-preserves-unspecified-fields"
GROUP = "state"
SERVICES = ["uxc"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:uxc-account-customizations")
def run(ctx) -> None:
    """PATCH semantics: a field omitted from the request body is left unchanged by the update."""
    uxc = ctx.client("uxc")
    snap = _snapshot(uxc)
    ctx.on_cleanup(lambda: _restore(uxc, snap))

    # Establish a known baseline across all three fields in one call. The region strings
    # here are opaque visibility-list membership values, not the endpoint the client
    # talks to, so pinning them is not a region-literal violation.
    uxc.update_account_customizations(
        accountColor="teal",
        visibleServices=["s3", "ec2"],
        visibleRegions=["us-east-1"],
    )

    # Update ONLY visibleRegions; accountColor and visibleServices are omitted.
    resp = uxc.update_account_customizations(visibleRegions=["eu-west-1", "ap-southeast-1"])

    # The field actually sent is echoed back.
    assert sorted(resp["visibleRegions"]) == ["ap-southeast-1", "eu-west-1"], (
        f"expected visibleRegions ['ap-southeast-1', 'eu-west-1'] echoed in the update "
        f"response, got {resp.get('visibleRegions')!r}"
    )

    # The omitted fields must be left unchanged in persisted state (checked via a fresh
    # read, since the update response is not guaranteed to echo fields absent from the
    # request).
    got = uxc.get_account_customizations()
    assert got["accountColor"] == "teal", (
        f"expected accountColor unchanged at 'teal' after an update omitting it, got {got.get('accountColor')!r}"
    )
    assert sorted(got["visibleServices"]) == ["ec2", "s3"], (
        f"expected visibleServices unchanged at ['ec2', 's3'] after an update omitting it, "
        f"got {got.get('visibleServices')!r}"
    )
    assert sorted(got["visibleRegions"]) == ["ap-southeast-1", "eu-west-1"], (
        f"expected visibleRegions ['ap-southeast-1', 'eu-west-1'] persisted, got {got.get('visibleRegions')!r}"
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
