"""filtered-pagination-reconstructs-full-filtered-set."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "filtered-pagination-reconstructs-full-filtered-set"
GROUP = "pagination"
SERVICES = ["bcm-recommended-actions"]


def _collect(client, **kwargs):
    items = []
    token = None
    for _ in range(500):
        params = dict(kwargs)
        if token:
            params["nextToken"] = token
        resp = client.list_recommended_actions(**params)
        items.extend(resp.get("recommendedActions", []))
        token = resp.get("nextToken")
        if not token:
            break
    else:
        raise AssertionError("pagination did not terminate within 500 pages")
    return items


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Paginating a FILTERED query with maxResults=1 must walk every page, never
    repeat an id, and reassemble to exactly the same id set as a single filtered
    call made without a page-size cap -- pagination and filtering compose."""

    client = ctx.client("bcm-recommended-actions")
    baseline = client.list_recommended_actions()["recommendedActions"]
    if not baseline:
        raise AssertionError(
            "account has zero recommended actions; there is no write API for this "
            "service so a severity value cannot be manufactured to filter on -- "
            "needs a sandbox account with at least one naturally-occurring action"
        )

    target_severity = baseline[0]["severity"]
    action_filter = {
        "actions": [{"key": "SEVERITY", "matchOption": "EQUALS", "values": [target_severity]}]
    }

    unpaginated = _collect(client, filter=action_filter)
    unpaginated_ids = {a["id"] for a in unpaginated}
    assert baseline[0]["id"] in unpaginated_ids, (
        f"baseline action {baseline[0]['id']} (severity={target_severity}) missing from "
        f"the unpaginated filtered result set {sorted(unpaginated_ids)}"
    )

    paged_ids: list[str] = []
    seen: set[str] = set()
    token = None
    for _ in range(500):
        kwargs = {"maxResults": 1, "filter": action_filter}
        if token:
            kwargs["nextToken"] = token
        page = client.list_recommended_actions(**kwargs)
        for action in page["recommendedActions"]:
            assert action["severity"] == target_severity, (
                f"filtered page returned action {action['id']} with severity "
                f"{action['severity']!r}, expected {target_severity!r}"
            )
            assert action["id"] not in seen, f"id {action['id']} repeated across pages"
            seen.add(action["id"])
            paged_ids.append(action["id"])
        token = page.get("nextToken")
        if not token:
            break
    else:
        raise AssertionError("filtered pagination did not terminate within 500 pages")

    assert set(paged_ids) == unpaginated_ids, (set(paged_ids), unpaginated_ids)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
