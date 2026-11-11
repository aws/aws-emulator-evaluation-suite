"""scan-exclusive-start-key-naming-an-attribute-outside-the-key-schema-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "scan-exclusive-start-key-naming-an-attribute-outside-the-key-schema-rejected"
GROUP = "pagination"
SERVICES = ["dynamodb"]
ERR_VALIDATION = "ValidationException"


def _error(fn):
    """``(Code, Message)`` for the ``ClientError`` ``fn`` raises; an unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Scan rejects an ExclusiveStartKey carrying an attribute outside the table's key schema,
    with ValidationException, and the rejected call writes nothing.
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
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 90})

    seed = {f"item-{i:03d}" for i in range(5)}
    for pk in sorted(seed):
        ddb.put_item(TableName=table, Item={"pk": {"S": pk}})

    # Positive control: a real, freshly minted ExclusiveStartKey continues the scan normally.
    first = ddb.scan(TableName=table, Limit=1, ConsistentRead=True)
    real_key = first["LastEvaluatedKey"]
    control = ddb.scan(TableName=table, ExclusiveStartKey=real_key, ConsistentRead=True)
    rest = {item["pk"]["S"] for item in control["Items"]}
    expected_rest = seed - {real_key["pk"]["S"]}
    assert rest == expected_rest, (
        f"positive control: resuming after {real_key['pk']['S']!r} returned {sorted(rest)!r}, "
        f"expected {sorted(expected_rest)!r}"
    )

    # Negative: the same key, plus one attribute the table's key schema does not declare.
    bad_key = dict(real_key, extra={"S": "unexpected"})
    code, message = _error(lambda: ddb.scan(TableName=table, ExclusiveStartKey=bad_key))
    assert code == ERR_VALIDATION, f"expected {ERR_VALIDATION}, got {code}: {message!r}"
    assert message == "The provided starting key is invalid", (
        f"expected AWS's exact ValidationException message, got {message!r}"
    )

    # The rejected call wrote nothing: the table still holds exactly the five seeded items.
    final = ddb.scan(TableName=table, ConsistentRead=True)["Items"]
    final_pks = {item["pk"]["S"] for item in final}
    assert final_pks == seed, f"expected the original seed {sorted(seed)!r} unchanged, got {sorted(final_pks)!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
