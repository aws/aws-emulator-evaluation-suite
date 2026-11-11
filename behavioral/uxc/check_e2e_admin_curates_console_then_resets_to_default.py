"""e2e-admin-curates-console-then-resets-to-default."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "e2e-admin-curates-console-then-resets-to-default"
GROUP = "e2e"
SERVICES = ["uxc"]


@tags("axis:happy-path", "cap:c1", "cap:c5", "concern:representation", "plane:control", "resource:account-singleton:uxc-account-customizations")
def run(ctx) -> None:
    """UpdateAccountCustomizations sets accountColor purple plus curated visibleServices and visibleRegions,
    GetAccountCustomizations reads them back, and a partial update resetting accountColor to "none" leaves both lists
    unchanged."""
    uxc = ctx.client("uxc")
    snap = _snapshot(uxc)
    ctx.on_cleanup(lambda: _restore(uxc, snap))

    # Step 1: discover the real service catalog (drives what visibleServices values are
    # legal downstream — proves ListServices output is genuinely usable, not just docs).
    curated_services = _collect_real_services(uxc, minimum=3)

    # Step 2: curate the console in one atomic call.
    curate_resp = uxc.update_account_customizations(
        accountColor="purple",
        visibleServices=curated_services,
        visibleRegions=["us-east-1", "eu-west-1"],
    )
    assert curate_resp["accountColor"] == "purple", (
        f"expected accountColor='purple' in update response, got {curate_resp.get('accountColor')!r}"
    )
    assert sorted(curate_resp["visibleServices"]) == sorted(curated_services), (
        f"expected visibleServices={sorted(curated_services)!r} in update response, "
        f"got {sorted(curate_resp.get('visibleServices', []))!r}"
    )
    assert sorted(curate_resp["visibleRegions"]) == ["eu-west-1", "us-east-1"], (
        f"expected visibleRegions=['eu-west-1', 'us-east-1'] in update response, "
        f"got {sorted(curate_resp.get('visibleRegions', []))!r}"
    )

    # Step 3: an independent read confirms durability of the curated state (not just an
    # echo of the write request).
    mid_state = uxc.get_account_customizations()
    assert mid_state["accountColor"] == "purple", (
        f"expected accountColor='purple' on independent read, got {mid_state.get('accountColor')!r}"
    )
    assert sorted(mid_state["visibleServices"]) == sorted(curated_services), (
        f"expected visibleServices={sorted(curated_services)!r} on independent read, "
        f"got {sorted(mid_state.get('visibleServices', []))!r}"
    )
    assert sorted(mid_state["visibleRegions"]) == ["eu-west-1", "us-east-1"], (
        f"expected visibleRegions=['eu-west-1', 'us-east-1'] on independent read, "
        f"got {sorted(mid_state.get('visibleRegions', []))!r}"
    )

    # Step 4: reset accountColor back to its documented default ("none") in a single
    # call, leaving visibleServices/visibleRegions untouched (PATCH semantics — they were
    # omitted from this request, so the response does not echo them back), then confirm
    # the result via an independent read.
    reset_resp = uxc.update_account_customizations(accountColor="none")
    assert reset_resp["accountColor"] == "none", (
        f"expected accountColor='none' in reset response, got {reset_resp.get('accountColor')!r}"
    )

    final_state = uxc.get_account_customizations()
    # Hard-subscript: accountColor must be PRESENT and equal to "none" on the independent
    # read. A `.get(..., "none")` default here would let a target that omits the field
    # entirely (rather than genuinely resetting it) pass this — the exact defect this
    # terminal assertion exists to catch.
    assert final_state["accountColor"] == "none", (
        f"expected accountColor='none' after reset on independent read, "
        f"got {final_state.get('accountColor')!r}"
    )
    assert sorted(final_state["visibleServices"]) == sorted(curated_services), (
        f"expected visibleServices={sorted(curated_services)!r} to survive the partial "
        f"reset unchanged, got {sorted(final_state.get('visibleServices', []))!r}"
    )
    assert sorted(final_state["visibleRegions"]) == ["eu-west-1", "us-east-1"], (
        f"expected visibleRegions=['eu-west-1', 'us-east-1'] to survive the partial reset "
        f"unchanged, got {sorted(final_state.get('visibleRegions', []))!r}"
    )


def _collect_real_services(uxc, minimum: int) -> list[str]:
    services: list[str] = []
    next_token = None
    while len(services) < minimum:
        kwargs = {"maxResults": 100}
        if next_token:
            kwargs["nextToken"] = next_token
        page = uxc.list_services(**kwargs)
        services.extend(page.get("services", []))
        next_token = page.get("nextToken")
        if not next_token:
            break
    assert len(services) >= minimum, (
        f"real service catalog only has {len(services)} entries; need at least {minimum}"
    )
    return services[:minimum]


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

