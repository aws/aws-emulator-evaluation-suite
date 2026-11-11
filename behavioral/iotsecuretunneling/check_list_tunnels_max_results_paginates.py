"""list-tunnels-max-results-paginates."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-tunnels-max-results-paginates"
GROUP = "state-machine"
SERVICES = ["iotsecuretunneling"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """maxResults caps a single ListTunnels page and nextToken lets the caller walk the rest."""
    client = ctx.client("iotsecuretunneling")
    tunnel_ids = []
    for _ in range(3):
        opened = client.open_tunnel(
            description=ctx.unique_name("sim2real-iot-tunnel-page-"),
            tags=[{"key": "purpose", "value": "sim2real-list-tunnels-pagination"}],
        )
        tid = opened["tunnelId"]
        tunnel_ids.append(tid)
        ctx.on_cleanup(lambda tid=tid: client.close_tunnel(tunnelId=tid, delete=True))

    page = client.list_tunnels(maxResults=1)
    assert len(page["tunnelSummaries"]) == 1, (
        f"expected maxResults=1 to cap the page at 1 tunnel, got {len(page['tunnelSummaries'])}"
    )
    assert "nextToken" in page and page["nextToken"], (
        "expected a nextToken when more tunnels remain beyond a 1-item page"
    )

    # Walk the rest with a larger page size (independent of the maxResults=1 assertion above)
    # so this check stays fast even on an account with a long tunnel history.
    seen_ids = set()
    next_token = None
    pages_walked = 0
    while pages_walked < 50:
        kwargs = {"maxResults": 100}
        if next_token:
            kwargs["nextToken"] = next_token
        page = client.list_tunnels(**kwargs)
        seen_ids.update(s["tunnelId"] for s in page["tunnelSummaries"])
        next_token = page.get("nextToken")
        pages_walked += 1
        if all(tid in seen_ids for tid in tunnel_ids) or not next_token:
            break

    assert set(tunnel_ids).issubset(seen_ids), "pagination did not surface all created tunnels"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
