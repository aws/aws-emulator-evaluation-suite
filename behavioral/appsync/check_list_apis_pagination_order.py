"""list-apis-pagination-order."""
from __future__ import annotations

import time
from typing import Any

from behavioral_harness import tags

CHECK = "list-apis-pagination-order"
GROUP = "ordering"
SERVICES = ["appsync"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListApis pagination lists every created Api exactly once, at page_size 1 and again at
    page_size 3; AppSync documents no ordering, so neither traversal's order is graded."""
    appsync = ctx.client("appsync")

    event_config = {
        "authProviders": [{"authType": "API_KEY"}],
        "connectionAuthModes": [{"authType": "API_KEY"}],
        "defaultPublishAuthModes": [{"authType": "API_KEY"}],
        "defaultSubscribeAuthModes": [{"authType": "API_KEY"}],
    }

    created_ids: list[str] = []
    for i in range(4):
        name = ctx.unique_name(f"sim2real-api-{i}-")
        api = appsync.create_api(
            name=name,
            eventConfig=event_config,
            tags={"sim2real": CHECK, "sim2real:managed": "true"},
        )["api"]
        api_id = api["apiId"]
        created_ids.append(api_id)
        ctx.on_cleanup(lambda aid=api_id: appsync.delete_api(apiId=aid))

    # Each traversal is polled (bounded) until it lists every created Api exactly once. The
    # listing is account-wide, so only this check's own ids are graded: another caller's creates
    # and deletes between pages move foreign entries, and a retried traversal settles them.
    for page_size in (1, 3):
        _poll_until(
            lambda ps=page_size: _collect_all_api_ids(appsync, page_size=ps),
            lambda ids: all(ids.count(cid) == 1 for cid in created_ids),
            timeout_s=_budget_s(ctx, 60.0),
            interval_s=2,
            ctx=ctx,
        )


#: Upper bound on the pages one listing walk follows.
_MAX_PAGES = 500


def _collect_all_api_ids(appsync: Any, page_size: int = 2) -> list[str]:
    ids: list[str] = []
    token = None
    for _ in range(_MAX_PAGES):
        kwargs: dict[str, Any] = {"maxResults": page_size}
        if token:
            kwargs["nextToken"] = token
        resp = appsync.list_apis(**kwargs)
        ids.extend(a["apiId"] for a in resp.get("apis", []))
        token = resp.get("nextToken")
        if not token:
            return ids
    raise AssertionError(f"ListApis still returned a nextToken after {_MAX_PAGES} pages")


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float, ctx):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    if _budget_spent(ctx):
        raise TimeoutError("ListApis listing every created Api once: the run budget ended first; "
                           "not graded")
    raise AssertionError(f"ListApis did not list each created Api exactly once within {timeout_s}s, "
                         f"last value: {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
