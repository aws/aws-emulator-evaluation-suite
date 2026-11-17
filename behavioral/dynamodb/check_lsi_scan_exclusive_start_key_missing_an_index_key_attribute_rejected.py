"""lsi-scan-exclusive-start-key-missing-an-index-key-attribute-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "lsi-scan-exclusive-start-key-missing-an-index-key-attribute-rejected"
GROUP = "lsi"
SERVICES = ["dynamodb"]
_INDEX = "lsi1"
ERR_VALIDATION = "ValidationException"


def _error(fn):
    """``(Code, Message)`` for the ``ClientError`` ``fn`` raises; an unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Scan over an LSI rejects an ExclusiveStartKey missing any one of its three key
    attributes with ValidationException, while a complete one resumes the walk and no rejected
    call changes the table's contents.
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddb-lsilekneg-")
    ddb.create_table(
        TableName=table,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}, {"AttributeName": "sk", "KeyType": "RANGE"}],
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
            {"AttributeName": "lsk", "AttributeType": "N"},
        ],
        LocalSecondaryIndexes=[{
            "IndexName": _INDEX,
            "KeySchema": [{"AttributeName": "pk", "KeyType": "HASH"}, {"AttributeName": "lsk", "KeyType": "RANGE"}],
            "Projection": {"ProjectionType": "ALL"},
        }],
        BillingMode="PAY_PER_REQUEST",
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    for i in range(5):
        ddb.put_item(TableName=table, Item={"pk": {"S": "p0"}, "sk": {"S": f"s{i:02d}"}, "lsk": {"N": str(i)}})

    first = ddb.scan(TableName=table, IndexName=_INDEX, ConsistentRead=True, Limit=1)
    assert [it["sk"]["S"] for it in first["Items"]] == ["s00"], first["Items"]
    real_key = first.get("LastEvaluatedKey")
    assert real_key == {"pk": {"S": "p0"}, "sk": {"S": "s00"}, "lsk": {"N": "0"}}, (
        f"expected the first item's three key attributes as the LastEvaluatedKey, got {real_key!r}"
    )

    # Positive control: the real, complete ExclusiveStartKey resumes the walk.
    cont = ddb.scan(TableName=table, IndexName=_INDEX, ConsistentRead=True, ExclusiveStartKey=real_key)
    cont_sks = [it["sk"]["S"] for it in cont["Items"]]
    assert cont_sks == [f"s{i:02d}" for i in range(1, 5)], (
        f"positive control: the real ExclusiveStartKey must resume after s00, got {cont_sks!r}"
    )

    for missing in ("pk", "sk", "lsk"):
        bad_key = {k: v for k, v in real_key.items() if k != missing}
        code, message = _error(
            lambda bad_key=bad_key: ddb.scan(
                TableName=table, IndexName=_INDEX, ConsistentRead=True, ExclusiveStartKey=bad_key,
            )
        )
        assert code == ERR_VALIDATION, (
            f"ExclusiveStartKey missing {missing!r}: expected {ERR_VALIDATION}, got {code}: {message!r}"
        )
        assert message == "The provided starting key is invalid", (
            f"ExclusiveStartKey missing {missing!r}: expected AWS's exact ValidationException "
            f"message, got {message!r}"
        )

    # None of the three rejected calls wrote, deleted or otherwise changed the table.
    final = ddb.scan(TableName=table, ConsistentRead=True)["Items"]
    final_sks = sorted(it["sk"]["S"] for it in final)
    assert final_sks == [f"s{i:02d}" for i in range(5)], (
        f"expected the original 5 items unchanged after the rejected calls, got {final_sks!r}"
    )

    # A second positive control: the real key still resumes the walk after the rejections.
    cont2 = ddb.scan(TableName=table, IndexName=_INDEX, ConsistentRead=True, ExclusiveStartKey=real_key)
    assert cont2["Items"] == cont["Items"], (
        f"the real ExclusiveStartKey's continuation changed after the rejected calls: "
        f"{cont2['Items']!r} vs {cont['Items']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
