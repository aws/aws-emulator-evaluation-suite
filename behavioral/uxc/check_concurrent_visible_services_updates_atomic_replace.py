"""concurrent-visible-services-updates-atomic-replace."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed

from behavioral_harness import tags

CHECK = "concurrent-visible-services-updates-atomic-replace"
GROUP = "concurrency"
SERVICES = ["uxc"]


@tags("axis:happy-path", "cap:c1", "cap:c5", "concern:representation", "plane:control", "resource:account-singleton:uxc-account-customizations")
def run(ctx) -> None:
    """Concurrent UpdateAccountCustomizations calls that each replace visibleServices with a different whole (real, catalog-valid) list never merge: the final state is exactly ONE of the racers' lists, never an interleaving of two."""
    uxc = ctx.client("uxc")
    snap = _snapshot(uxc)
    ctx.on_cleanup(lambda: _restore(uxc, snap))

    real_services = _collect_real_services(uxc, minimum=18)
    racer_count = 6
    candidates = [
        sorted(real_services[i * 3:(i + 1) * 3]) for i in range(racer_count)
    ]

    def _apply(services: list[str]) -> None:
        uxc.update_account_customizations(visibleServices=services)

    with ThreadPoolExecutor(max_workers=racer_count) as pool:
        futures = [pool.submit(_apply, c) for c in candidates]
        for f in as_completed(futures):
            f.result()  # surface any exception from a racer

    final = sorted(uxc.get_account_customizations()["visibleServices"])

    matches = [c for c in candidates if c == final]
    assert len(matches) == 1, (
        f"final visibleServices {final!r} must equal exactly one full racer list, "
        f"but matched {len(matches)} of {len(candidates)} candidates (possible merge/corruption)"
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
        f"real service catalog only has {len(services)} entries; need at least {minimum} "
        "to build distinct racer lists"
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
