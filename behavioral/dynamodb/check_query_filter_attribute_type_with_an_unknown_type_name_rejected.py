"""query-filter-attribute-type-with-an-unknown-type-name-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "query-filter-attribute-type-with-an-unknown-type-name-rejected"
GROUP = "negative-classes"
SERVICES = ["dynamodb"]

#: The ten DynamoDB attribute type descriptors; attribute_type's second operand is checked against
#: exactly this closed set.
_VALID_TYPES = frozenset({"S", "SS", "N", "NS", "B", "BS", "BOOL", "NULL", "L", "M"})


def _error(fn) -> tuple:
    """The (code, message) of the ClientError fn() raises. RAISES when fn() unexpectedly succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Query FilterExpression attribute_type's type operand is matched case-sensitively against
    the ten type descriptors; a name outside that set is refused and the legal form still works.
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-qdatypneg-")
    ddb.create_table(
        TableName=table,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}, {"AttributeName": "sk", "KeyType": "RANGE"}],
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
        ],
        BillingMode="PAY_PER_REQUEST",
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    ddb.put_item(TableName=table, Item={"pk": {"S": "p1"}, "sk": {"S": "a"}, "attr": {"N": "1"}})

    def rejected(type_name: str) -> None:
        code, message = _error(lambda: ddb.query(
            TableName=table, KeyConditionExpression="pk = :p",
            FilterExpression="attribute_type(#a, :t)",
            ExpressionAttributeNames={"#a": "attr"},
            ExpressionAttributeValues={":p": {"S": "p1"}, ":t": {"S": type_name}},
        ))
        assert code == "ValidationException", (
            f"{type_name!r} raised {code!r} ({message!r}), expected 'ValidationException'"
        )
        want_head = (
            f"Invalid FilterExpression: Invalid attribute type name found; type: {type_name}, "
            "valid types: {"
        )
        assert message[: len(want_head)] == want_head and message[-1:] == "}", (
            f"{type_name!r} raised message {message!r}, expected it wrapped by {want_head!r} and '}}'"
        )
        # The ten type names are fixed, but their listed order is not: the set, not the string, is
        # the invariant.
        assert frozenset(message[len(want_head): -1].split(",")) == _VALID_TYPES, (
            f"{type_name!r} raised message {message!r}, expected it to name exactly "
            f"{sorted(_VALID_TYPES)}"
        )

    rejected("XX")
    # "n" is a real type letter, lower-cased: the ten descriptors are matched case-sensitively, not
    # folded, so a real type name spelled wrong is refused exactly like a wholly unknown one.
    rejected("n")

    control = ddb.query(
        TableName=table, KeyConditionExpression="pk = :p",
        FilterExpression="attribute_type(#a, :t)",
        ExpressionAttributeNames={"#a": "attr"},
        ExpressionAttributeValues={":p": {"S": "p1"}, ":t": {"S": "N"}},
        ConsistentRead=True,
    )
    assert control["Count"] == 1, f"attribute_type(attr, N) matched {control['Count']!r}, expected 1"
    assert control["Items"] == [{"pk": {"S": "p1"}, "sk": {"S": "a"}, "attr": {"N": "1"}}], (
        f"the legal Query returned {control['Items']!r}, expected the original item unchanged"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
