"""describe-db-subnet-groups-marker-pagination-enumerates-every-group-once."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "describe-db-subnet-groups-marker-pagination-enumerates-every-group-once"
GROUP = "subnet_groups"
SERVICES = ["rds"]

# One more than MaxRecords' documented minimum (20), so a single MaxRecords=20 page can never
# hold every group this check creates and a second page is always required.
_GROUP_COUNT = 21


@tags("axis:happy-path", "cap:c2", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeDBSubnetGroups paginates on Marker: paging through with MaxRecords at its
    documented minimum visits every created group exactly once, with no group missed or
    repeated across pages.
    """
    rds = ctx.client("rds")
    net = ctx.network()
    azs = sorted(net.subnets)
    if len(azs) < 2:
        raise AssertionError(f"the shared network only spans {azs!r}; at least 2 AZs are needed")
    subnet_ids = [net.subnets[azs[0]], net.subnets[azs[1]]]

    prefix = ctx.unique_name("sim2real-behav-sngpg-")
    names = [f"{prefix}{i:02d}" for i in range(_GROUP_COUNT)]
    for group_name in names:
        rds.create_db_subnet_group(
            DBSubnetGroupName=group_name,
            DBSubnetGroupDescription="sim2real behavioral pagination check",
            SubnetIds=subnet_ids,
            Tags=[{"Key": "sim2real", "Value": "true"}],
        )
        ctx.on_cleanup(lambda group_name=group_name: rds.delete_db_subnet_group(DBSubnetGroupName=group_name))

    seen: list[str] = []
    saw_marker = False
    marker = None
    while True:
        kwargs = {"MaxRecords": 20}
        if marker is not None:
            kwargs["Marker"] = marker
        page = rds.describe_db_subnet_groups(**kwargs)
        page_names = [g["DBSubnetGroupName"] for g in page["DBSubnetGroups"]]
        assert len(page_names) <= 20, f"page carried {len(page_names)} groups, over MaxRecords=20"
        seen.extend(page_names)
        marker = page.get("Marker")
        if marker:
            saw_marker = True
        else:
            break

    assert saw_marker, (
        f"created {_GROUP_COUNT} groups with MaxRecords=20, but no page carried a Marker: "
        "pagination was never exercised"
    )
    assert len(seen) == len(set(seen)), (
        f"pagination repeated a group across pages: {sorted(n for n in set(seen) if seen.count(n) > 1)}"
    )
    assert set(names) <= set(seen), (
        f"missing from the paginated enumeration: {sorted(set(names) - set(seen))}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
