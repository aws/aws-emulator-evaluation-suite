"""execute-transaction-index-select-top-level-validation-not-cancellation."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "execute-transaction-index-select-top-level-validation-not-cancellation"
GROUP = "partiql"
SERVICES = ["dynamodb"]


def _error(fn):
    """(Error.Code, Error.Message, response) of the ClientError fn() raises; a success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message"), exc.response
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A SELECT addressed at a GSI inside ExecuteTransaction is a top-level ValidationException
    naming the statement, never a TransactionCanceledException; the same statement inside
    BatchExecuteStatement instead fails only that slot and leaves its sibling intact.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_ExecuteTransaction.html
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}, {"AttributeName": "sk", "KeyType": "RANGE"}],
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
            {"AttributeName": "gpk", "AttributeType": "S"},
        ],
        GlobalSecondaryIndexes=[{
            "IndexName": "gsi1",
            "KeySchema": [{"AttributeName": "gpk", "KeyType": "HASH"}],
            "Projection": {"ProjectionType": "ALL"},
        }],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 30})

    left = ctx.time_left()
    deadline = time.monotonic() + (60.0 if left is None else max(1.0, min(60.0, left - 5.0)))
    gsi_status = None
    while True:
        described = ddb.describe_table(TableName=table)["Table"]
        gsi_status = {i["IndexName"]: i["IndexStatus"] for i in described.get("GlobalSecondaryIndexes", [])}
        if gsi_status.get("gsi1") == "ACTIVE" or time.monotonic() >= deadline:
            break
        time.sleep(2)
    assert gsi_status.get("gsi1") == "ACTIVE", f"gsi1 never became ACTIVE: {gsi_status!r}"

    ddb.put_item(TableName=table, Item={"pk": {"S": "p1"}, "sk": {"S": "s1"}, "gpk": {"S": "g1"}})

    index_select = f'SELECT * FROM "{table}"."gsi1" WHERE gpk=\'g1\''

    code, message, response = _error(
        lambda: ddb.execute_transaction(TransactStatements=[{"Statement": index_select}])
    )
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    assert code != "TransactionCanceledException", "an index-qualified SELECT must fail validation, not cancellation"
    expected = "Validation failed in TransactStatements[0]: Reads on indices are not supported within transactions."
    assert message == expected, f"unexpected message: {message!r}"
    assert "CancellationReasons" not in response["Error"], (
        f"a top-level validation failure carries no per-statement CancellationReasons, got {response['Error']!r}"
    )

    # Positive control: ExecuteTransaction itself still works for a base-table read.
    good_txn = ddb.execute_transaction(
        TransactStatements=[{"Statement": f'SELECT * FROM "{table}" WHERE pk=\'p1\' AND sk=\'s1\''}]
    )["Responses"]
    assert good_txn[0]["Item"]["gpk"] == {"S": "g1"}, (
        f"expected a base-table ExecuteTransaction SELECT to succeed, got {good_txn!r}"
    )

    resp = ddb.batch_execute_statement(Statements=[
        {"Statement": index_select},
        {"Statement": f'SELECT * FROM "{table}" WHERE pk=\'p1\' AND sk=\'s1\''},
    ])
    responses = resp["Responses"]
    assert len(responses) == 2, f"expected 2 per-statement responses, got {len(responses)}: {responses}"

    bad_slot = responses[0]
    assert "Item" not in bad_slot, f"expected the index-qualified SELECT slot to carry no Item, got {bad_slot}"
    slot_error = bad_slot.get("Error")
    assert slot_error is not None, (
        f"expected the index-qualified SELECT to be a per-slot Error, not a thrown exception "
        f"aborting the whole batch, got {bad_slot!r}"
    )
    assert slot_error.get("Code") == "ValidationError", f"expected Code ValidationError, got {slot_error.get('Code')!r}"
    expected_batch_msg = "Select statements within BatchExecuteStatement must specify the primary key in the where clause."
    assert slot_error.get("Message") == expected_batch_msg, f"unexpected message: {slot_error.get('Message')!r}"

    good_slot = responses[1]
    assert "Error" not in good_slot, f"expected the base-table SELECT sibling to succeed, got {good_slot}"
    assert good_slot.get("Item", {}).get("gpk") == {"S": "g1"}, (
        f"expected the sibling slot to return the seeded item, got {good_slot}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
