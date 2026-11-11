"""list-rules-pagination-with-max-results."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-rules-pagination-with-max-results"
GROUP = "lifecycle"
SERVICES = ["rbin"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListRules with a small MaxResults pages correctly via NextToken: each page has
    at most MaxResults items, pages don't repeat rules, and the union covers all created rules."""
    rbin = ctx.client("rbin")

    rule_ids = []
    for _ in range(3):
        rule_id = rbin.create_rule(
            ResourceType="EC2_IMAGE",
            RetentionPeriod={"RetentionPeriodValue": 3, "RetentionPeriodUnit": "DAYS"},
            Description=ctx.unique_name("sim2real-rbin-page-"),
        )["Identifier"]
        rule_ids.append(rule_id)
        ctx.on_cleanup(lambda rid=rule_id: rbin.delete_rule(Identifier=rid))

    seen: list[str] = []
    token = None
    pages = 0
    while True:
        kwargs = {"ResourceType": "EC2_IMAGE", "MaxResults": 1}
        if token:
            kwargs["NextToken"] = token
        resp = rbin.list_rules(**kwargs)
        page_ids = [r["Identifier"] for r in resp.get("Rules", [])]
        assert len(page_ids) <= 1, (
            f"ListRules with MaxResults=1 returned {len(page_ids)} rules in one page: {page_ids}"
        )
        seen.extend(page_ids)
        pages += 1
        token = resp.get("NextToken")
        if not token or pages > 50:
            break

    assert len(seen) == len(set(seen)), "ListRules paginated with duplicate rules across pages"
    for rule_id in rule_ids:
        assert rule_id in seen, (
            f"created rule {rule_id} did not appear across any paginated ListRules page; saw {seen}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
