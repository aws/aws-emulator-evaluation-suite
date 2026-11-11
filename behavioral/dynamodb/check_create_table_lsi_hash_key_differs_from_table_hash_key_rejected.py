"""create-table-lsi-hash-key-differs-from-table-hash-key-rejected."""

from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-table-lsi-hash-key-differs-from-table-hash-key-rejected"
GROUP = "table_lifecycle"
SERVICES = ["dynamodb"]
ERR_VALIDATION = "ValidationException"


def _error(fn):
    """Call fn(); return (code, message). An unexpected SUCCESS raises rather than returning a
    falsy sentinel."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _delete_table_if_exists(ddb, table_name):
    try:
        ddb.delete_table(TableName=table_name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateTable rejects a LocalSecondaryIndex whose leading hash key differs from the base
    table's hash key, naming the index and both hash keys. An LSI must share the table's hash key.
    """
    ddb = ctx.client("dynamodb")
    ctrl_name = ctx.unique_name("sim2real-behav-lsi-hash-ctrl-")
    name = ctx.unique_name("sim2real-behav-lsi-hash-mismatch-")
    ctx.on_cleanup(lambda: _delete_table_if_exists(ddb, ctrl_name))
    ctx.on_cleanup(lambda: _delete_table_if_exists(ddb, name))

    # Positive control: the identical LSI, sharing the table's hash key, must succeed -- proves
    # CreateTable+LSI works on this account/credentials before the negative below is trusted to
    # mean "rejected for this reason" rather than "rejects everything".
    ddb.create_table(
        TableName=ctrl_name,
        KeySchema=[
            {"AttributeName": "pk", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
            {"AttributeName": "lsi_sk", "AttributeType": "S"},
        ],
        LocalSecondaryIndexes=[
            {
                "IndexName": "lsi1",
                "KeySchema": [
                    {"AttributeName": "pk", "KeyType": "HASH"},
                    {"AttributeName": "lsi_sk", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            }
        ],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ddb.get_waiter("table_exists").wait(TableName=ctrl_name, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    ctrl_desc = ddb.describe_table(TableName=ctrl_name)["Table"]
    ctrl_lsi_names = [idx["IndexName"] for idx in ctrl_desc.get("LocalSecondaryIndexes", [])]
    assert "lsi1" in ctrl_lsi_names, f"positive control did not create the LSI: {ctrl_desc!r}"

    # Negative: the LSI's leading key (other) is not the table's hash key (pk).
    code, message = _error(
        lambda: ddb.create_table(
            TableName=name,
            KeySchema=[
                {"AttributeName": "pk", "KeyType": "HASH"},
                {"AttributeName": "sk", "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "pk", "AttributeType": "S"},
                {"AttributeName": "sk", "AttributeType": "S"},
                {"AttributeName": "other", "AttributeType": "S"},
                {"AttributeName": "lsi_sk", "AttributeType": "S"},
            ],
            LocalSecondaryIndexes=[
                {
                    "IndexName": "lsi1",
                    "KeySchema": [
                        {"AttributeName": "other", "KeyType": "HASH"},
                        {"AttributeName": "lsi_sk", "KeyType": "RANGE"},
                    ],
                    "Projection": {"ProjectionType": "ALL"},
                }
            ],
            BillingMode="PAY_PER_REQUEST",
            Tags=[{"Key": "sim2real", "Value": CHECK}],
        )
    )
    assert code == ERR_VALIDATION, f"expected {ERR_VALIDATION}, got {code!r}"
    expected_msg = (
        "One or more parameter values were invalid: Index KeySchema does not have the same "
        "leading hash key as table KeySchema for index: lsi1. index hash key: other, table hash "
        "key: pk"
    )
    assert message == expected_msg, f"expected message {expected_msg!r}, got {message!r}"

    # The rejected CreateTable must not have left a stray table behind.
    exists_code, exists_msg = _error(lambda: ddb.describe_table(TableName=name))
    assert exists_code == "ResourceNotFoundException", (
        f"the refused CreateTable left {name!r} behind: DescribeTable gave {exists_code!r}"
    )
    expected_nf = f"Requested resource not found: Table: {name} not found"
    assert exists_msg == expected_nf, f"expected message {expected_nf!r}, got {exists_msg!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
