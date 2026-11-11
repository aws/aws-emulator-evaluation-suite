"""execute-transaction-exceeds-100-statements-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "execute-transaction-exceeds-100-statements-rejected"
GROUP = "partiql"
SERVICES = ["dynamodb"]
ERR_VALIDATION = "ValidationException"


def _error_code(fn):
    """The error code and message fn() raises; RAISES if the call unexpectedly succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code"), exc.response.get("Error", {}).get("Message")
    raise AssertionError(f"expected ExecuteTransaction to be rejected, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """ExecuteTransaction with exactly 100 statements commits them all; 101 statements is rejected
    with ValidationException and writes nothing.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/ql-reference.multiplestatements.transactions.html
    """
    ddb = ctx.client("dynamodb")
    t = ctx.unique_name("sim2real-behav-")
    ddb.create_table(
        TableName=t,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real-behav", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=t))
    ddb.get_waiter("table_exists").wait(TableName=t, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    insert_stmt = f"INSERT INTO \"{t}\" VALUE {{'pk': ?}}"
    at_limit_pks = [f"etxn-atlimit-{i}" for i in range(100)]
    at_limit = [{"Statement": insert_stmt, "Parameters": [{"S": pk}]} for pk in at_limit_pks]
    ddb.execute_transaction(TransactStatements=at_limit)
    first = ddb.get_item(TableName=t, Key={"pk": {"S": "etxn-atlimit-0"}}, ConsistentRead=True)
    assert "Item" in first, "a transaction at the documented 100-statement ceiling must be applied in full"
    last = ddb.get_item(TableName=t, Key={"pk": {"S": "etxn-atlimit-99"}}, ConsistentRead=True)
    assert "Item" in last, "a transaction at the documented 100-statement ceiling must be applied in full"

    over_pks = [f"etxn-over100-{i}" for i in range(101)]
    too_many = [{"Statement": insert_stmt, "Parameters": [{"S": pk}]} for pk in over_pks]
    code, message = _error_code(lambda: ddb.execute_transaction(TransactStatements=too_many))
    assert code == ERR_VALIDATION, f"expected {ERR_VALIDATION}, got {code!r}"
    # The rendered list between these carries a per-statement object identity hash that varies
    # request to request; the prefix and suffix around it are the stable, documented contract.
    prefix = "1 validation error detected: Value '["
    suffix = (
        "]' at 'transactStatements' failed to satisfy constraint: "
        "Member must have length less than or equal to 100"
    )
    assert message.startswith(prefix) and message.endswith(suffix), (
        f"expected the ValidationException message to start with {prefix!r} and end with "
        f"{suffix!r}, got {message!r}"
    )

    rejected = ddb.get_item(TableName=t, Key={"pk": {"S": "etxn-over100-0"}}, ConsistentRead=True)
    assert "Item" not in rejected, "a rejected oversized transaction must not have written any item"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
