"""put-item-list-holding-string-set-sole-empty-string-member-round-trips."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "put-item-list-holding-string-set-sole-empty-string-member-round-trips"
GROUP = "representation"
SERVICES = ["dynamodb"]


@tags("axis:happy-path", "cap:c2", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutItem accepts an L element holding a string set whose only member is the empty
    string, and a later GetItem reads the set back with that one member intact.
    """
    ddb = ctx.client("dynamodb")
    t = ctx.unique_name("sim2real-behav-ddb-lss-")
    ddb.create_table(
        TableName=t,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=t))
    ddb.get_waiter("table_exists").wait(TableName=t, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    ddb.put_item(TableName=t, Item={"pk": {"S": "x"}, "attr": {"L": [{"SS": [""]}]}})

    got = ddb.get_item(TableName=t, Key={"pk": {"S": "x"}}, ConsistentRead=True).get("Item")
    assert got is not None, "an L holding an SS whose only member is the empty string must be stored"
    assert got["attr"] == {"L": [{"SS": [""]}]}, (
        f"GetItem must read back the L element as [{{'SS': ['']}}], got {got['attr']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
