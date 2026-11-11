"""list-log-groups-paginates-all-groups."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-log-groups-paginates-all-groups"
GROUP = "state-machine"
SERVICES = ["logs"]

_COUNT = 5


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListLogGroups returns every created log group exactly once across nextToken pages."""
    logs = ctx.client("logs")
    prefix = ctx.unique_name("sim2real-behav-llg-")
    created = []
    for i in range(_COUNT):
        name = f"{prefix}{i}"
        logs.create_log_group(logGroupName=name, tags={"Sim2RealOwner": "behavioral-suite"})
        ctx.on_cleanup(lambda n=name: logs.delete_log_group(logGroupName=n))
        created.append(name)

    def _paginate_with_limit_1():
        seen = []
        next_token = None
        pages = 0
        while True:
            kwargs = {"logGroupNamePattern": prefix, "limit": 1}
            if next_token:
                kwargs["nextToken"] = next_token
            resp = logs.list_log_groups(**kwargs)
            page_names = [g["logGroupName"] for g in resp.get("logGroups", [])]
            seen.extend(page_names)
            pages += 1
            next_token = resp.get("nextToken")
            if not next_token or pages > _COUNT + 5:
                break
        return pages, seen

    # Newly created log groups are not necessarily visible to ListLogGroups the instant
    # CreateLogGroup returns, so poll (bounded) until the index has caught up to all of them
    # before asserting on the pagination shape.
    pages, seen = _poll_until(
        _paginate_with_limit_1,
        lambda result: set(result[1]) == set(created),
    )

    assert pages >= _COUNT, f"expected pagination across >= {_COUNT} pages with limit=1, got {pages}"
    assert len(seen) == len(set(seen)), f"duplicate log groups returned across pages: {seen}"
    assert set(seen) == set(created), f"expected {sorted(created)}, got {sorted(seen)}"


def _poll_until(fn, predicate, timeout=30, interval=1.0):
    import time

    deadline = time.monotonic() + timeout
    result = fn()
    while not predicate(result):
        if time.monotonic() >= deadline:
            pages, seen = result
            raise AssertionError(
                f"timed out after {timeout}s waiting for ListLogGroups to index all created "
                f"log groups; last poll saw {pages} page(s), groups={sorted(seen)}"
            )
        time.sleep(interval)
        result = fn()
    return result


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
