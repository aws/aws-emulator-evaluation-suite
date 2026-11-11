"""list-workload-estimates-pagination-includes-all-created."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-workload-estimates-pagination-includes-all-created"
GROUP = "listing"
SERVICES = ["bcm-pricing-calculator"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Paging through ListWorkloadEstimates with MaxResults=1 eventually surfaces every created estimate."""
    client = ctx.client("bcm-pricing-calculator")

    created_ids = set()
    for _ in range(3):
        name = ctx.unique_name("sim2real-we-")
        estimate_id = client.create_workload_estimate(name=name)["id"]
        created_ids.add(estimate_id)
        ctx.on_cleanup(lambda eid=estimate_id: _delete_workload_estimate(client, eid))

    seen_ids = set()
    next_token = None
    page_count = 0
    for _ in range(1000):
        kwargs = {"maxResults": 1}
        if next_token:
            kwargs["nextToken"] = next_token
        page = client.list_workload_estimates(**kwargs)
        items = page["items"]
        assert len(items) <= 1, (
            f"expected at most maxResults=1 item per page, got {len(items)} on page {page_count + 1}"
        )
        seen_ids.update(i["id"] for i in items)
        page_count += 1
        next_token = page.get("nextToken")
        if not next_token:
            break

    assert page_count >= len(created_ids), (
        f"expected at least {len(created_ids)} pages of maxResults=1 to cover the created "
        f"estimates, only paged {page_count} times"
    )
    assert created_ids.issubset(seen_ids), (
        f"expected every created workload estimate id {sorted(created_ids)} to surface while "
        f"paging with maxResults=1, only saw {sorted(seen_ids)}"
    )


# ===== helpers =====
def _delete_workload_estimate(client, estimate_id):
    from botocore.exceptions import ClientError

    try:
        client.delete_workload_estimate(identifier=estimate_id)
    except ClientError as err:
        if err.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
