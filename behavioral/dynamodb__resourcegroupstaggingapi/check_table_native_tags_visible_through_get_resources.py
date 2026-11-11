"""table-native-tags-visible-through-get-resources."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "table-native-tags-visible-through-get-resources"
GROUP = "tagging-discovery"
SERVICES = ["dynamodb", "resourcegroupstaggingapi"]


@tags("axis:happy-path", "cap:c2", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A tag added with DynamoDB TagResource appears in tagging API GetResources filtered to
    dynamodb:table with the table's ARN, and DynamoDB UntagResource removes it from that index."""
    ddb = ctx.client("dynamodb")
    rgt = ctx.client("resourcegroupstaggingapi")

    table_name = ctx.unique_name("sim2real-behav-tbl-")
    key = ctx.unique_name("sim2real-behav-k-")
    value = ctx.unique_name("sim2real-behav-v-")

    created = ddb.create_table(
        TableName=table_name,
        AttributeDefinitions=[{"AttributeName": "id", "AttributeType": "S"}],
        KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}],
        BillingMode="PAY_PER_REQUEST",
    )
    table_arn = created["TableDescription"]["TableArn"]
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table_name))
    ddb.get_waiter("table_exists").wait(TableName=table_name, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    ddb.tag_resource(ResourceArn=table_arn, Tags=[{"Key": key, "Value": value}])

    # The tagging index is eventually consistent, so poll a bounded window.

    found = _poll_until(
        lambda: rgt.get_resources(
            ResourceTypeFilters=["dynamodb:table"],
            TagFilters=[{"Key": key, "Values": [value]}],
        )["ResourceTagMappingList"],
        lambda mappings: len(mappings) == 1,
        timeout_s=120.0,
    )
    assert len(found) == 1, f"GetResources matched {len(found)} resources, expected exactly 1: {found!r}"
    assert found[0]["ResourceARN"] == table_arn, (
        f"discovered ARN {found[0]['ResourceARN']!r} does not equal the table's own ARN {table_arn!r}"
    )
    index_tags = {t["Key"]: t["Value"] for t in found[0]["Tags"]}
    assert index_tags.get(key) == value, (
        f"tagging-api index reports tags {index_tags!r}, missing {key}={value!r}"
    )

    ddb.untag_resource(ResourceArn=table_arn, TagKeys=[key])

    gone = _poll_until(
        lambda: rgt.get_resources(
            ResourceTypeFilters=["dynamodb:table"],
            TagFilters=[{"Key": key, "Values": [value]}],
        )["ResourceTagMappingList"],
        lambda mappings: mappings == [],
        timeout_s=120.0,
    )
    assert gone == [], (
        f"UntagResource removed {key}={value!r} from DynamoDB's own tag list, but the tagging "
        f"index still reports {gone!r}"
    )


def _poll_until(probe, predicate, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = probe()
    while time.monotonic() < deadline:
        if predicate(last):
            return last
        time.sleep(interval_s)
        last = probe()
    return last


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
