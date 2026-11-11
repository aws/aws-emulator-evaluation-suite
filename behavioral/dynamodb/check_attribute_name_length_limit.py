"""attribute-name-length-limit."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "attribute-name-length-limit"
GROUP = 'limits'
SERVICES = ['dynamodb']
ERR_VALIDATION = 'ValidationException'


@tags(
    "axis:happy-path", "cap:c1", "concern:data-plane", "concern:representation",
    "concern:negative-classes", "dp:api", "plane:data",
)
def run(ctx) -> None:
    """The modeled AttributeName shape allows up to 65535 bytes for an item attribute name (distinct
    from the 255-byte KeySchemaAttributeName cap that applies only to key/index attribute names) —
    a name at that max round-trips, and a name one byte over it is rejected."""
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-')
    ddb.create_table(
        TableName=table,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    max_name = 'a' * 65535
    ddb.put_item(TableName=table, Item={'pk': {'S': 'long-attr'}, max_name: {'S': 'value'}})
    got = ddb.get_item(TableName=table, Key={'pk': {'S': 'long-attr'}}, ConsistentRead=True).get('Item')
    assert got is not None and got.get(max_name) == {'S': 'value'}, (
        f"expected a {len(max_name)}-byte attribute name to round-trip, got item {got!r}"
    )

    over_name = 'a' * 65536
    try:
        ddb.put_item(TableName=table, Item={'pk': {'S': 'over-attr'}, over_name: {'S': 'value'}})
        raise AssertionError(
            f"expected PutItem with a {len(over_name)}-byte attribute name to be rejected, it succeeded"
        )
    except ClientError as exc:
        code = exc.response.get('Error', {}).get('Code')
        message = exc.response.get('Error', {}).get('Message')
        assert code == ERR_VALIDATION, f"expected {ERR_VALIDATION} for a {len(over_name)}-byte attribute name, got {code!r}"
        assert message == "1 validation error detected: Attribute name is too large, must be less than 65536 bytes", (
            f"expected AWS's exact ValidationException message, got {message!r}"
        )

    absent = ddb.get_item(TableName=table, Key={'pk': {'S': 'over-attr'}}, ConsistentRead=True).get('Item')
    assert absent is None, f"expected no item written for the rejected over-length attribute name, got {absent!r}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
