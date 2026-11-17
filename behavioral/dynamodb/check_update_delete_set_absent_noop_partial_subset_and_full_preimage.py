"""update-delete-set-absent-noop-partial-subset-and-full-preimage."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "update-delete-set-absent-noop-partial-subset-and-full-preimage"
GROUP = "update-expression"
SERVICES = ["dynamodb"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """UpdateItem DELETE on an attribute the item lacks is a silent no-op; DELETE of a proper
    subset of a Number Set leaves the exact remainder, and UPDATED_OLD reports the full
    pre-delete set rather than only the removed members.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_UpdateItem.html
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    key = {"pk": {"S": "item"}}
    ddb.put_item(TableName=table, Item={**key, "nums": {"NS": ["1", "2", "3", "4"]}, "keep": {"S": "k"}})

    # DELETE against an attribute the item never had: no error, nothing to report back.
    resp = ddb.update_item(
        TableName=table, Key=key, UpdateExpression="DELETE ghost :v",
        ExpressionAttributeValues={":v": {"SS": ["z"]}}, ReturnValues="UPDATED_OLD",
    )
    assert "Attributes" not in resp, (
        f"DELETE of a never-set attribute with UPDATED_OLD must report nothing, got {resp.get('Attributes')!r}"
    )
    unaffected = ddb.get_item(TableName=table, Key=key, ConsistentRead=True)["Item"]
    assert set(unaffected["nums"]["NS"]) == {"1", "2", "3", "4"}, (
        f"a no-op DELETE must leave sibling attributes untouched, got {unaffected['nums']!r}"
    )
    assert unaffected["keep"] == {"S": "k"}, f"a no-op DELETE must leave sibling attributes untouched, got {unaffected!r}"

    # DELETE of a proper subset of the Number Set: UPDATED_OLD is the full pre-delete set, not
    # just the two removed members.
    old = ddb.update_item(
        TableName=table, Key=key, UpdateExpression="DELETE nums :v",
        ExpressionAttributeValues={":v": {"NS": ["1", "2"]}}, ReturnValues="UPDATED_OLD",
    ).get("Attributes")
    assert set(old["nums"]["NS"]) == {"1", "2", "3", "4"}, (
        f"UPDATED_OLD after a subset DELETE must be the full pre-delete set, got {old['nums']!r}"
    )

    remainder = ddb.get_item(TableName=table, Key=key, ConsistentRead=True)["Item"]
    assert set(remainder["nums"]["NS"]) == {"3", "4"}, (
        f"DELETE of a proper subset must leave the exact remainder, got {remainder['nums']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
