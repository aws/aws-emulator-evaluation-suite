"""legacy-attributes-to-get-duplicate-name-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "legacy-attributes-to-get-duplicate-name-rejected"
GROUP = "legacy"
SERVICES = ["dynamodb"]

_VALIDATION = "ValidationException"
_DUPLICATE_MSG = "One or more parameter values were invalid: Duplicate value in attribute name: name"


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "concern:data-plane", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """A duplicated attribute name in a base-table legacy AttributesToGet is ValidationException
    for GetItem, BatchGetItem, Query and Scan alike; the same name used once succeeds.
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddbattgdup-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    key = {"pk": {"S": "p1"}}
    ddb.put_item(TableName=table, Item={**key, "name": {"S": "alpha"}})

    code, message = _error(lambda: ddb.get_item(TableName=table, Key=key,
                                                 AttributesToGet=["name", "name"], ConsistentRead=True))
    assert (code, message) == (_VALIDATION, _DUPLICATE_MSG), f"GetItem with a duplicate name gave {code!r}: {message!r}"
    control = ddb.get_item(TableName=table, Key=key, AttributesToGet=["name"], ConsistentRead=True)
    assert control["Item"] == {"name": {"S": "alpha"}}, f"control GetItem returned {control['Item']!r}"

    code, message = _error(lambda: ddb.batch_get_item(RequestItems={
        table: {"Keys": [key], "AttributesToGet": ["name", "name"], "ConsistentRead": True}}))
    assert (code, message) == (_VALIDATION, _DUPLICATE_MSG), f"BatchGetItem with a duplicate name gave {code!r}: {message!r}"
    control_batch = ddb.batch_get_item(RequestItems={
        table: {"Keys": [key], "AttributesToGet": ["name"], "ConsistentRead": True}})
    assert control_batch["Responses"][table] == [{"name": {"S": "alpha"}}], (
        f"control BatchGetItem returned {control_batch['Responses'][table]!r}"
    )

    key_conditions = {"pk": {"AttributeValueList": [{"S": "p1"}], "ComparisonOperator": "EQ"}}
    code, message = _error(lambda: ddb.query(TableName=table, KeyConditions=key_conditions,
                                             AttributesToGet=["name", "name"], ConsistentRead=True))
    assert (code, message) == (_VALIDATION, _DUPLICATE_MSG), f"Query with a duplicate name gave {code!r}: {message!r}"
    control_query = ddb.query(TableName=table, KeyConditions=key_conditions,
                              AttributesToGet=["name"], ConsistentRead=True)
    assert control_query["Items"] == [{"name": {"S": "alpha"}}], (
        f"control Query returned {control_query['Items']!r}"
    )

    code, message = _error(lambda: ddb.scan(TableName=table, AttributesToGet=["name", "name"],
                                            ConsistentRead=True))
    assert (code, message) == (_VALIDATION, _DUPLICATE_MSG), f"Scan with a duplicate name gave {code!r}: {message!r}"
    control_scan = ddb.scan(TableName=table, AttributesToGet=["name"], ConsistentRead=True)
    assert control_scan["Items"] == [{"name": {"S": "alpha"}}], (
        f"control Scan returned {control_scan['Items']!r}"
    )

    # None of the four refused calls wrote anything: the table still holds only the one item.
    final = ddb.scan(TableName=table, ConsistentRead=True)
    assert final["Count"] == 1, f"expected the one item put above and nothing else, got {final!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
