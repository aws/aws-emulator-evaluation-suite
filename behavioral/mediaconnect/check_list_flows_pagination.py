"""list-flows-pagination."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-flows-pagination"
GROUP = "data-plane"
SERVICES = ["mediaconnect"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListFlows with a small MaxResults paginates via NextToken, and paging through
    to completion surfaces every flow created in this account/region exactly once,
    without truncation or duplication."""
    mc = ctx.client("mediaconnect")
    created_arns = set()
    for _ in range(2):
        arn = mc.create_flow(
            Name=ctx.unique_name("sim2real-mc-flow-"),
            Source={"Name": "source1", "Protocol": "rtp", "WhitelistCidr": "203.0.113.0/24"},
            FlowTags={"sim2real:managed": "true"},
        )["Flow"]["FlowArn"]
        created_arns.add(arn)
        ctx.on_cleanup(lambda a=arn: mc.delete_flow(FlowArn=a))

    seen_arns: list[str] = []
    token = None
    pages = 0
    while True:
        kwargs = {"MaxResults": 1}
        if token:
            kwargs["NextToken"] = token
        resp = mc.list_flows(**kwargs)
        pages += 1
        seen_arns.extend(f["FlowArn"] for f in resp.get("Flows", []))
        token = resp.get("NextToken")
        if not token or pages > 500:
            break

    assert pages >= 2, "MaxResults=1 across >=2 flows should force multiple pages"
    assert created_arns.issubset(set(seen_arns)), (
        f"expected all created flows {created_arns} to be paged over; saw {set(seen_arns)}"
    )
    assert len(seen_arns) == len(set(seen_arns)), "ListFlows returned a duplicate FlowArn"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
