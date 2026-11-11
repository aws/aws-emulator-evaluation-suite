"""execute-transaction-client-token-idempotent-mismatch-rejected."""
from __future__ import annotations

import time
import uuid

from behavioral_harness import tags

CHECK = "execute-transaction-client-token-idempotent-mismatch-rejected"
GROUP = "overly-permissive"
SERVICES = ["dynamodb"]

_TAGS_KV = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
]


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Reusing an ExecuteTransaction ClientRequestToken with identical parameters is a safe replay;
    reusing it with different parameters fails with IdempotentParameterMismatchException and
    leaves the original item unchanged."""
    ddb = ctx.client("dynamodb")
    table_name = ctx.unique_name("sim2real-behav-ddb-")
    ddb.create_table(
        TableName=table_name,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=_TAGS_KV,
    )
    ctx.on_cleanup(lambda: _safe_delete_table(ddb, table_name))
    _wait_table_active(ddb, table_name)

    token = str(uuid.uuid4())
    statement = f'INSERT INTO "{table_name}" VALUE {{\'pk\': ?, \'val\': ?}}'
    original_params = [{"S": "idem-item"}, {"S": "v1"}]

    ddb.execute_transaction(
        TransactStatements=[{"Statement": statement, "Parameters": original_params}],
        ClientRequestToken=token,
    )
    got = ddb.get_item(TableName=table_name, Key={"pk": {"S": "idem-item"}})
    assert got.get("Item", {}).get("val", {}).get("S") == "v1", (
        f"expected v1 after the initial insert, got {got.get('Item')!r}"
    )

    # Positive control: without it, rejecting every reused token would pass the mismatch leg.
    ddb.execute_transaction(
        TransactStatements=[{"Statement": statement, "Parameters": original_params}],
        ClientRequestToken=token,
    )
    replayed = ddb.get_item(TableName=table_name, Key={"pk": {"S": "idem-item"}})
    assert replayed.get("Item", {}).get("val", {}).get("S") == "v1", (
        f"identical-payload replay must not alter state, got {replayed.get('Item')!r}"
    )

    code, message = _error_code_and_message(
        lambda: ddb.execute_transaction(
            TransactStatements=[
                {
                    "Statement": statement,
                    "Parameters": [{"S": "idem-item"}, {"S": "v2-DIFFERENT"}],
                }
            ],
            ClientRequestToken=token,
        )
    )
    assert code == "IdempotentParameterMismatchException", (
        f"expected IdempotentParameterMismatchException, got {code!r}"
    )
    expected_message = (
        "Specified idempotent token was used with different request parameters within the "
        "idempotency window"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    still = ddb.get_item(TableName=table_name, Key={"pk": {"S": "idem-item"}})
    assert still.get("Item", {}).get("val", {}).get("S") == "v1", (
        f"expected v1 to survive the rejected mismatched retry, got {still.get('Item')!r}"
    )


def _error_code_and_message(fn):
    """Return fn()'s error code and message; an unexpected success raises AssertionError."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(
        f"real DynamoDB rejects a reused ClientRequestToken with different parameters, but the "
        f"call SUCCEEDED and returned {result!r}"
    )


def _wait_table_active(ddb, table_name, timeout_s=120.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        desc = ddb.describe_table(TableName=table_name)["Table"]
        if desc["TableStatus"] == "ACTIVE":
            return desc
        time.sleep(interval_s)
    raise AssertionError(f"table {table_name} never became ACTIVE")


def _safe_delete_table(ddb, table_name):
    from botocore.exceptions import ClientError

    try:
        ddb.delete_table(TableName=table_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
