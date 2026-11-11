"""reserved-word-bare-rejected-across-update-filter-and-projection."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "reserved-word-bare-rejected-across-update-filter-and-projection"
GROUP = "expressions"
SERVICES = ["dynamodb"]
ERR_VALIDATION = "ValidationException"


def _error(fn) -> tuple:
    """The (code, message) of the ClientError fn() raises. RAISES when fn() unexpectedly succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A bare reserved word as an attribute name is rejected with ValidationException in Update,
    Filter and Projection expressions, each with its own message; a rejected update writes nothing.
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-rsvd-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    key = {"pk": {"S": "rsvd-1"}}
    original = {**key, "status": {"S": "active"}, "name": {"S": "widget"}, "note": {"S": "x"}}
    ddb.put_item(TableName=table, Item=original)

    # --- UpdateExpression: bare `status` is rejected; the item is untouched. ---
    code, message = _error(lambda: ddb.update_item(
        TableName=table, Key=key, UpdateExpression="SET status = :v",
        ExpressionAttributeValues={":v": {"S": "changed"}},
    ))
    assert code == ERR_VALIDATION, f"UpdateExpression bare reserved word answered {code!r} ({message!r})"
    expected_update = (
        "1 validation error detected: Invalid UpdateExpression: Attribute name is a reserved "
        "keyword; reserved keyword: status"
    )
    assert message == expected_update, f"expected message {expected_update!r}, got {message!r}"
    after_update = ddb.get_item(TableName=table, Key=key, ConsistentRead=True)["Item"]
    assert after_update == original, (
        f"item after the rejected UpdateItem is {after_update!r}, expected it unchanged at "
        f"{original!r}"
    )

    # --- FilterExpression: bare `name` is rejected. ---
    code, message = _error(lambda: ddb.scan(
        TableName=table, FilterExpression="name = :v",
        ExpressionAttributeValues={":v": {"S": "widget"}},
    ))
    assert code == ERR_VALIDATION, f"FilterExpression bare reserved word answered {code!r} ({message!r})"
    expected_filter = (
        "Invalid FilterExpression: Attribute name is a reserved keyword; reserved keyword: name"
    )
    assert message == expected_filter, f"expected message {expected_filter!r}, got {message!r}"

    # --- ProjectionExpression: bare `status` is rejected. ---
    code, message = _error(lambda: ddb.get_item(
        TableName=table, Key=key, ProjectionExpression="status",
    ))
    assert code == ERR_VALIDATION, f"ProjectionExpression bare reserved word answered {code!r} ({message!r})"
    expected_projection = (
        "Invalid ProjectionExpression: Attribute name is a reserved keyword; reserved keyword: status"
    )
    assert message == expected_projection, f"expected message {expected_projection!r}, got {message!r}"

    # Positive control: all three mechanisms work once the reserved word is aliased, so the
    # rejections above are attributable to the bare keyword, not to Update/Filter/Projection
    # being broken outright.
    updated = ddb.update_item(
        TableName=table, Key=key, UpdateExpression="SET #s = :v",
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={":v": {"S": "changed"}},
        ReturnValues="UPDATED_NEW",
    )
    assert updated["Attributes"] == {"status": {"S": "changed"}}, (
        f"aliased UpdateExpression returned {updated['Attributes']!r}, expected status=changed"
    )
    filtered = ddb.scan(
        TableName=table, FilterExpression="#n = :v",
        ExpressionAttributeNames={"#n": "name"},
        ExpressionAttributeValues={":v": {"S": "widget"}},
        ConsistentRead=True,
    )
    assert filtered["Count"] == 1, f"aliased FilterExpression matched {filtered['Count']!r}, expected 1"
    projected = ddb.get_item(
        TableName=table, Key=key, ProjectionExpression="#s",
        ExpressionAttributeNames={"#s": "status"},
        ConsistentRead=True,
    )
    assert projected["Item"] == {"status": {"S": "changed"}}, (
        f"aliased ProjectionExpression returned {projected['Item']!r}, expected only status=changed"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
