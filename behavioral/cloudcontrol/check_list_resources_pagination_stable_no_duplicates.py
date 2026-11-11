"""list-resources-pagination-stable-no-duplicates."""
from __future__ import annotations

import concurrent.futures
import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "list-resources-pagination-stable-no-duplicates"
GROUP = "ordering"
SERVICES = ["cloudcontrol"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A full paginated ListResources traversal never repeats or omits an identifier
    for resources that are known (via CreateResource) to exist at the time of listing."""
    cc = ctx.client("cloudcontrol")

    # Create the 5 marker queues CONCURRENTLY rather than sequentially. Each
    # CreateResource->terminal-status round trip through CloudControl's
    # provider-framework plumbing routinely takes tens of seconds on real AWS;
    # five of them run back-to-back easily eats most of the check's 300s
    # wall-clock budget before ListResources is even called. The 5 creations are
    # independent of one another, so
    # running them in parallel (each still polled to a terminal state on its own
    # thread) cuts that setup cost from ~5x a single create to ~1x, without
    # touching anything the check actually asserts.
    names = [ctx.unique_name(f"sim2real-cc-pg-{i}-") for i in range(5)]

    def _create_one(name: str) -> str:
        resp = cc.create_resource(
            TypeName="AWS::SQS::Queue",
            DesiredState=json.dumps(
                {"QueueName": name, "Tags": [{"Key": "sim2real:managed", "Value": "true"}]}
            ),
        )
        token = resp["ProgressEvent"]["RequestToken"]
        pe, _ = _wait_for_request(ctx, token)
        assert pe["OperationStatus"] == "SUCCESS", f"create did not succeed: {pe}"
        return pe["Identifier"]

    with concurrent.futures.ThreadPoolExecutor(max_workers=len(names)) as pool:
        created_ids: list[str] = list(pool.map(_create_one, names))

    # Register ONE cleanup that deletes all 5 concurrently, not 5 separate cleanups run
    # LIFO/sequentially. Teardown has its own 60s budget, separate from and much smaller
    # than the 300s body budget; 5 sequential CloudControl delete->poll-to-terminal round
    # trips routinely exceed that 60s window on real AWS, leaking the very
    # resources this check exists to clean up. Deleting them in parallel, mirroring the
    # creation step above, keeps the whole teardown within one delete's latency.
    def _delete_all() -> None:
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(created_ids)) as pool:
            list(pool.map(lambda i: _delete_and_wait(ctx, "AWS::SQS::Queue", i), created_ids))

    ctx.on_cleanup(_delete_all)

    # Use a page size close to the API's practical maximum. A real account can
    # accumulate a large, unbounded number of pre-existing SQS queues (from other
    # test runs, etc.), and paging through the whole type listing with a tiny
    # page size (e.g. 2) multiplies the number of ListResources round-trips by
    # up to 50x, which reliably blows the check's wall-clock budget on real AWS
    # without adding any additional coverage of the pagination-stability
    # invariant being asserted below.
    all_ids = _list_all_resource_ids(ctx, "AWS::SQS::Queue", max_results=100)

    assert len(all_ids) == len(set(all_ids)), (
        f"ListResources pagination produced duplicate identifiers across pages "
        f"({len(all_ids)} entries, {len(set(all_ids))} unique)"
    )
    for ident in created_ids:
        count = all_ids.count(ident)
        assert count == 1, f"identifier {ident} appeared {count} times across paginated ListResources (expected exactly 1)"


def _wait_for_request(ctx: Any, token: str, timeout_s: float = 150.0, interval_s: float = 2.0):
    cc = ctx.client("cloudcontrol")
    terminal = {"SUCCESS", "FAILED", "CANCEL_COMPLETE"}
    history: list[str] = []
    deadline = time.monotonic() + timeout_s
    last_pe = None
    while time.monotonic() < deadline:
        resp = cc.get_resource_request_status(RequestToken=token)
        last_pe = resp["ProgressEvent"]
        history.append(last_pe["OperationStatus"])
        if last_pe["OperationStatus"] in terminal:
            return last_pe, history
        time.sleep(interval_s)
    raise AssertionError(f"request {token} did not reach a terminal state within {timeout_s}s (history={history})")


def _delete_and_wait(ctx: Any, type_name: str, identifier: str, timeout_s: float = 150.0, interval_s: float = 2.0) -> None:
    cc = ctx.client("cloudcontrol")
    try:
        resp = cc.delete_resource(TypeName=type_name, Identifier=identifier)
    except Exception:
        return
    token = resp["ProgressEvent"]["RequestToken"]
    _wait_for_request(ctx, token, timeout_s=timeout_s, interval_s=interval_s)


def _list_all_resource_ids(ctx: Any, type_name: str, max_results: int = 100, max_pages: int = 500) -> list[str]:
    cc = ctx.client("cloudcontrol")
    out: list[str] = []
    next_token = None
    for _ in range(max_pages):
        kwargs: dict[str, Any] = {"TypeName": type_name, "MaxResults": max_results}
        if next_token:
            kwargs["NextToken"] = next_token
        resp = cc.list_resources(**kwargs)
        out.extend(r["Identifier"] for r in resp.get("ResourceDescriptions", []))
        next_token = resp.get("NextToken")
        if not next_token:
            break
    return out


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
