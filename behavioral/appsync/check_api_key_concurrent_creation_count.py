"""api-key-concurrent-creation-count."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from behavioral_harness import tags

CHECK = "api-key-concurrent-creation-count"
GROUP = "concurrency"
SERVICES = ["appsync"]

_N = 5


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Firing N CreateApiKey calls concurrently against the same API produces
    exactly N distinct keys with no lost writes or duplicate IDs under contention."""
    appsync = ctx.client("appsync")
    api = _create_graphql_api(ctx)
    api_id = api["apiId"]

    def _create(i):
        # Real AppSync briefly holds a per-API "schema is being altered" lock right after
        # CreateGraphqlApi finishes provisioning (the freshly-created default schema settling in
        # the background); CreateApiKey calls that land on the API in that window are rejected
        # with ConcurrentModificationException rather than being queued. That's a real, transient
        # per-API lock conflict -- not a lost write -- so retry it with backoff same as botocore's
        # own standard-mode retry treats throttling, and still let a genuinely persistent
        # conflict surface as a failure.
        deadline = time.monotonic() + 60.0
        delay = 1.0
        while True:
            try:
                return appsync.create_api_key(apiId=api_id, description=f"racer-{i}")["apiKey"]["id"]
            except Exception as exc:  # noqa: BLE001
                from botocore.exceptions import ClientError

                if not isinstance(exc, ClientError):
                    raise
                if exc.response.get("Error", {}).get("Code") != "ConcurrentModificationException":
                    raise
                if time.monotonic() >= deadline:
                    raise
                time.sleep(delay)
                delay = min(delay * 2, 10.0)

    ids = []
    with ThreadPoolExecutor(max_workers=_N) as pool:
        futures = [pool.submit(_create, i) for i in range(_N)]
        for fut in as_completed(futures):
            ids.append(fut.result())

    assert len(ids) == _N, f"expected {_N} successful creates, got {len(ids)}"
    assert len(set(ids)) == _N, f"duplicate key ids under concurrency: {ids}"

    listed_ids = {k["id"] for k in appsync.list_api_keys(apiId=api_id)["apiKeys"]}
    assert set(ids) <= listed_ids, (
        f"not all concurrently-created keys are visible: created={ids} listed={listed_ids}"
    )
    assert len(listed_ids) == _N, f"expected exactly {_N} keys total, found {len(listed_ids)}"


def _create_graphql_api(ctx, auth_type="API_KEY"):
    appsync = ctx.client("appsync")
    resp = appsync.create_graphql_api(
        name=ctx.unique_name("sim2real-behav-"),
        authenticationType=auth_type,
        tags={"sim2real": CHECK},
    )
    api = resp["graphqlApi"]
    api_id = api["apiId"]
    ctx.on_cleanup(lambda: appsync.delete_graphql_api(apiId=api_id))
    return api


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
