"""execute-transaction-malformed-statement-rejects-whole-call."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "execute-transaction-malformed-statement-rejects-whole-call"
GROUP = "partiql"
SERVICES = ["dynamodb"]
ERR_VALIDATION = "ValidationException"
ERR_TRANSACTION_CANCELED = "TransactionCanceledException"

_TAGS_KV = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
]


def _error_code_and_message(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected ExecuteTransaction to be rejected, but it SUCCEEDED with {result!r}")


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
    """ExecuteTransaction with one syntactically malformed statement rejects the whole call
    with ValidationException, never TransactionCanceledException, and no statement in the
    transaction — malformed or well-formed — takes effect.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_ExecuteTransaction.html
    """
    ddb = ctx.client("dynamodb")
    table_name = ctx.unique_name("sim2real-behav-ddb-etxn-")
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

    well_formed = f"INSERT INTO \"{table_name}\" VALUE {{'pk':'well-formed','sk':'s1'}}"
    malformed = f"INSRT INTO \"{table_name}\" VALUE {{'pk':'malformed','sk':'s1'}}"

    code, message = _error_code_and_message(
        lambda: ddb.execute_transaction(TransactStatements=[{"Statement": malformed}, {"Statement": well_formed}])
    )
    assert code == ERR_VALIDATION, f"expected {ERR_VALIDATION}, got {code!r} (never {ERR_TRANSACTION_CANCELED})"
    expected_message = (
        "Validation failed in TransactStatements[0]: "
        "Statement wasn't well formed, can't be processed: Unexpected token after expression"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    unwritten_malformed = ddb.get_item(
        TableName=table_name, Key={"pk": {"S": "malformed"}, "sk": {"S": "s1"}}, ConsistentRead=True
    )
    assert "Item" not in unwritten_malformed, (
        f"malformed statement must not have written, got {unwritten_malformed.get('Item')!r}"
    )
    unwritten_sibling = ddb.get_item(
        TableName=table_name, Key={"pk": {"S": "well-formed"}, "sk": {"S": "s1"}}, ConsistentRead=True
    )
    assert "Item" not in unwritten_sibling, (
        f"the well-formed sibling must not have taken effect either, got {unwritten_sibling.get('Item')!r}"
    )

    # Positive control: the identical well-formed statement alone succeeds, proving the
    # rejection above is attributable to the malformed statement, not a broken table or API.
    ddb.execute_transaction(TransactStatements=[{"Statement": well_formed}])
    written = ddb.get_item(
        TableName=table_name, Key={"pk": {"S": "well-formed"}, "sk": {"S": "s1"}}, ConsistentRead=True
    )
    assert "Item" in written, f"expected the positive control to have written, got {written!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
