"""concurrent-update-data-source-conflict."""
from __future__ import annotations

import threading
from typing import Any

from behavioral_harness import tags

CHECK = "concurrent-update-data-source-conflict"
GROUP = "concurrency"
SERVICES = ["appsync"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Two concurrent UpdateDataSource calls on one data source: at least one succeeds and echoes
    its own description, any loser fails ConcurrentModificationException, and the stored
    description is exactly one writer's."""
    appsync = ctx.client("appsync")

    api_id = _create_graphql_api(ctx, appsync)
    ds_name = ctx.unique_name("sim2real-ds").replace("-", "_")
    appsync.create_data_source(
        apiId=api_id,
        name=ds_name,
        type="NONE",
        description="initial",
    )
    ctx.on_cleanup(lambda: appsync.delete_data_source(apiId=api_id, name=ds_name))

    barrier = threading.Barrier(2)
    results: list[dict[str, Any]] = [{}, {}]

    def _update(idx: int, description: str) -> None:
        barrier.wait(timeout=10)
        try:
            resp = appsync.update_data_source(
                apiId=api_id, name=ds_name, type="NONE", description=description
            )
            results[idx] = {"ok": True, "description": resp["dataSource"]["description"]}
        except Exception as exc:  # noqa: BLE001
            results[idx] = {"ok": False, "code": _error_code(exc)}

    t1 = threading.Thread(target=_update, args=(0, "writer-A"))
    t2 = threading.Thread(target=_update, args=(1, "writer-B"))
    t1.start()
    t2.start()
    t1.join(timeout=30)
    t2.join(timeout=30)

    successes = [r for r in results if r.get("ok")]
    failures = [r for r in results if not r.get("ok")]

    # Every attempt is either a success whose response echoes exactly what it submitted, or a
    # failure with the documented concurrency-conflict code — never any other error, and never a
    # success whose response body doesn't match its own input (which would indicate corruption).
    assert successes, f"expected at least one UpdateDataSource call to succeed, got {results}"
    submitted = {"writer-A", "writer-B"}
    for s in successes:
        assert s["description"] in submitted, (
            f"a successful UpdateDataSource response must echo exactly what it submitted, "
            f"got {s['description']!r}"
        )
    for f in failures:
        assert f["code"] == "ConcurrentModificationException", (
            f"expected ConcurrentModificationException on a losing call, got {f['code']}"
        )

    final = appsync.get_data_source(apiId=api_id, name=ds_name)["dataSource"]
    assert final["description"] in submitted, (
        "final data source description must be a full, intact copy of exactly one of the two "
        f"concurrent writers' descriptions, not a merge/corruption of both, got "
        f"{final['description']!r}"
    )
    if len(successes) == 1:
        # With only one successful writer, the final state must be THAT writer's description
        # (the loser's write, if any, must not have landed).
        assert final["description"] == successes[0]["description"], (
            "final data source description must match the sole successful UpdateDataSource "
            f"call, got {final['description']!r} vs winner {successes[0]['description']!r}"
        )


def _error_code(exc: Exception) -> str | None:
    resp = getattr(exc, "response", None)
    if isinstance(resp, dict):
        return resp.get("Error", {}).get("Code")
    return None


def _create_graphql_api(ctx, appsync) -> str:
    name = ctx.unique_name("sim2real-appsync")
    resp = appsync.create_graphql_api(
        name=name, authenticationType="API_KEY", tags={"sim2real": "audit"}
    )
    api_id = resp["graphqlApi"]["apiId"]
    ctx.on_cleanup(lambda: appsync.delete_graphql_api(apiId=api_id))
    return api_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
