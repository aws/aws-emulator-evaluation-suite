"""concurrent-create-application-idempotent-client-token."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "concurrent-create-application-idempotent-client-token"
GROUP = "concurrency"
SERVICES = ["emr-serverless"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """N concurrent CreateApplication calls sharing the same clientToken and identical parameters all
    resolve to exactly one application (the idempotency token is honored under contention)."""
    emrs = ctx.client("emr-serverless")
    name = ctx.unique_name("sim2real-emrs-app-")
    token = ctx.unique_name("sim2real-emrs-tok-")

    def worker():
        return emrs.create_application(
            name=name, releaseLabel="emr-7.9.0", type="SPARK", clientToken=token
        )["applicationId"]

    with ThreadPoolExecutor(max_workers=8) as pool:
        futures = [pool.submit(worker) for _ in range(8)]
        results = [f.result() for f in futures]

    distinct_ids = set(results)
    for created_id in distinct_ids:
        ctx.on_cleanup(lambda created_id=created_id: emrs.delete_application(applicationId=created_id))
    assert len(distinct_ids) == 1, f"expected a single idempotent applicationId, got {distinct_ids}"
    app_id = distinct_ids.pop()

    # confirm only one application with this name exists (no duplicate racer slipped through).
    matches = [a for a in _list_all(emrs) if a["name"] == name]
    assert len(matches) == 1, f"expected exactly one application named {name!r}, found {len(matches)}"


def _list_all(emrs):
    apps: list[dict] = []
    token = None
    while True:
        kwargs = {"maxResults": 50}
        if token:
            kwargs["nextToken"] = token
        page = emrs.list_applications(**kwargs)
        apps.extend(page["applications"])
        token = page.get("nextToken")
        if not token:
            break
    return apps


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
