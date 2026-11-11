"""list-services-pagination-no-duplicates."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-services-pagination-no-duplicates"
GROUP = "state"
SERVICES = ["service-quotas"]


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListServices walked page by page through NextToken yields at least 50 ServiceCodes with no
    duplicates."""
    sq = ctx.client("service-quotas")
    seen: list[str] = []
    token = None
    for _ in range(200):
        kwargs = {"MaxResults": 5}
        if token:
            kwargs["NextToken"] = token
        resp = sq.list_services(**kwargs)
        for svc in resp["Services"]:
            seen.append(svc["ServiceCode"])
        token = resp.get("NextToken")
        if not token:
            break
    else:
        raise AssertionError("ListServices pagination did not terminate within 200 pages")

    assert len(seen) == len(set(seen)), "duplicate ServiceCode returned across pages"
    assert len(seen) >= 50, f"expected at least 50 services, got {len(seen)}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
