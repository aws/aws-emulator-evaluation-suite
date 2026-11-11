"""batch-execute-statement-malformed-slot-siblings-execute."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "batch-execute-statement-malformed-slot-siblings-execute"
GROUP = "partiql"
SERVICES = ["dynamodb"]

_TAGS_KV = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
]


def _wait_for_table_active(ddb, table_name, timeout_s=120.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = ddb.describe_table(TableName=table_name)["Table"]["TableStatus"]
        if status == "ACTIVE":
            return status
        time.sleep(interval_s)
    raise AssertionError(f"table {table_name} never went ACTIVE in {timeout_s}s (last={status})")


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """BatchExecuteStatement carries a malformed statement's failure as that slot's
    BatchStatementResponse.Error, and the well-formed sibling statements in the same
    call still execute.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_BatchExecuteStatement.html
    """
    ddb = ctx.client("dynamodb")
    table_name = ctx.unique_name("sim2real-behav-ddb-batch-")
    ddb.create_table(
        TableName=table_name,
        KeySchema=[
            {"AttributeName": "pk", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
        ],
        BillingMode="PAY_PER_REQUEST",
        Tags=_TAGS_KV,
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table_name))
    _wait_for_table_active(ddb, table_name)

    resp = ddb.batch_execute_statement(
        Statements=[
            {"Statement": f"INSRT INTO \"{table_name}\" VALUE {{'pk':'malformed','sk':'s1'}}"},
            {"Statement": f"INSERT INTO \"{table_name}\" VALUE {{'pk':'sibling-a','sk':'s1'}}"},
            {"Statement": f"INSERT INTO \"{table_name}\" VALUE {{'pk':'sibling-b','sk':'s1'}}"},
        ]
    )
    responses = resp["Responses"]
    assert len(responses) == 3, f"expected 3 per-statement responses, got {len(responses)}: {responses!r}"

    malformed = responses[0]
    assert "Item" not in malformed and "TableName" not in malformed, (
        f"expected the malformed slot to carry no effect, got {malformed!r}"
    )
    error = malformed.get("Error")
    assert error is not None, (
        f"expected the malformed slot to carry a per-slot Error (not abort the whole batch), got {malformed!r}"
    )
    assert error.get("Code") == "ValidationError", f"expected Code ValidationError, got {error.get('Code')!r}"
    expected_message = "Statement wasn't well formed, can't be processed: Unexpected token after expression"
    assert error.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {error.get('Message')!r}"
    )
    unwritten = ddb.get_item(
        TableName=table_name, Key={"pk": {"S": "malformed"}, "sk": {"S": "s1"}}, ConsistentRead=True
    )
    assert "Item" not in unwritten, f"malformed statement must not have written, got {unwritten.get('Item')!r}"

    # Positive control: the well-formed siblings in the SAME batch call executed.
    for slot, pk in ((responses[1], "sibling-a"), (responses[2], "sibling-b")):
        assert "Error" not in slot, f"expected sibling {pk!r} to succeed, got {slot!r}"
        written = ddb.get_item(TableName=table_name, Key={"pk": {"S": pk}, "sk": {"S": "s1"}}, ConsistentRead=True)
        assert "Item" in written, f"expected sibling {pk!r} to have been written, got {written!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
