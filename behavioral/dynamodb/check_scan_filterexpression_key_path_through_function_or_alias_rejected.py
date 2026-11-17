"""scan-filterexpression-key-path-through-function-or-alias-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "scan-filterexpression-key-path-through-function-or-alias-rejected"
GROUP = "scan"
SERVICES = ["dynamodb"]

_SCALAR_MSG = (
    "Key attributes must be scalars; list random access '[]' and map lookup '.' are "
    "not allowed: Key: pk"
)

# (FilterExpression, ExpressionAttributeNames) — every nested form a Scan can route
# a document path into the hash key through: inside attribute_exists(), through an
# alias, and through an aliased bracket index, plus a plain aliased comparison for
# control.
_NESTED_FORMS = (
    ("attribute_exists(pk.foo)", None),
    ("attribute_exists(pk[0])", None),
    ("attribute_exists(#a.foo)", {"#a": "pk"}),
    ("attribute_exists(#a[0])", {"#a": "pk"}),
    ("#a[0] = :v", {"#a": "pk"}),
    ("#a.foo = :v", {"#a": "pk"}),
)


def _error(fn) -> tuple:
    """The (code, message) ``fn`` is refused with. An unexpected success raises, naming it."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Scan FilterExpression reaching a nested path into the hash key is refused as a
    non-scalar key, whether the path sits inside attribute_exists(), is bracket-indexed,
    or is reached through an alias; a whole-key or non-key filter still matches.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Query.FilterExpression.html
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddb-scankeypath-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}, {"AttributeName": "sk", "KeyType": "RANGE"}],
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
        ],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    item = {"pk": {"S": "p1"}, "sk": {"S": "s1"}, "color": {"S": "red"}}
    ddb.put_item(TableName=table, Item=item)

    # Positive controls: a plain and an aliased reference to the whole key attribute,
    # and a filter on a non-key attribute, all still match — the refusals below are
    # about the nested path, not about naming the key or about FilterExpression itself.
    plain = ddb.scan(TableName=table, FilterExpression="attribute_exists(pk)", ConsistentRead=True)
    assert plain["Items"] == [item], f"attribute_exists(pk) returned {plain['Items']!r}, expected {[item]!r}"

    aliased = ddb.scan(
        TableName=table, FilterExpression="#a = :v", ConsistentRead=True,
        ExpressionAttributeNames={"#a": "pk"}, ExpressionAttributeValues={":v": {"S": "p1"}},
    )
    assert aliased["Items"] == [item], f"#a = :v (pk aliased) returned {aliased['Items']!r}, expected {[item]!r}"

    non_key = ddb.scan(
        TableName=table, FilterExpression="color = :c", ConsistentRead=True,
        ExpressionAttributeValues={":c": {"S": "red"}},
    )
    assert non_key["Items"] == [item], f"color = :c returned {non_key['Items']!r}, expected {[item]!r}"

    for expr, names in _NESTED_FORMS:
        kwargs = {"TableName": table, "FilterExpression": expr}
        if ":v" in expr:
            kwargs["ExpressionAttributeValues"] = {":v": {"S": "p1"}}
        if names:
            kwargs["ExpressionAttributeNames"] = names
        code, msg = _error(lambda kwargs=kwargs: ddb.scan(**kwargs))
        assert (code, msg) == ("ValidationException", _SCALAR_MSG), (
            f"Scan FilterExpression {expr!r} gave {code!r}: {msg!r}, expected ValidationException: {_SCALAR_MSG!r}"
        )

    rows = ddb.scan(TableName=table, ConsistentRead=True)["Items"]
    assert rows == [item], f"the table changed across the refused scans: {rows!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
