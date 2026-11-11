"""ddb-execute-statement-and-transaction-against-absent-table."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "ddb-execute-statement-and-transaction-against-absent-table"
GROUP = "partiql"
SERVICES = ["dynamodb"]

_NOT_FOUND = ("ResourceNotFoundException", "Requested resource not found")
_CANCELLED = (
    "TransactionCanceledException",
    "Transaction cancelled, please refer cancellation reasons for specific reasons [ResourceNotFound]",
)


def _error(fn) -> tuple:
    """The (code, message, response) a ClientError from fn() carries; raises on an unexpected success."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message"), exc.response
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """ExecuteStatement naming a missing table is ResourceNotFoundException; ExecuteTransaction
    naming one is TransactionCanceledException with a ResourceNotFound cancellation reason, not a
    top-level ResourceNotFoundException.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/ql-reference.multiplestatements.transactions.html
    """
    ddb = ctx.client("dynamodb")
    table = _make_table(ctx)
    absent = ctx.unique_name("sim2real-ddb-execabsent-")

    select_present = f'SELECT * FROM "{table}" WHERE pk = \'k1\''
    select_absent = f'SELECT * FROM "{absent}" WHERE pk = \'k1\''

    present = ddb.execute_statement(Statement=select_present)
    assert present["Items"] == [{"pk": {"S": "k1"}}], (
        f"ExecuteStatement on the real table returned {present['Items']!r}, expected the seeded item"
    )

    code, msg, _ = _error(lambda: ddb.execute_statement(Statement=select_absent))
    assert (code, msg) == _NOT_FOUND, (
        f"ExecuteStatement naming a missing table gave {code!r}: {msg!r}, expected {_NOT_FOUND!r}"
    )

    present_txn = ddb.execute_transaction(TransactStatements=[{"Statement": select_present}])
    assert present_txn["Responses"][0]["Item"] == {"pk": {"S": "k1"}}, (
        f"ExecuteTransaction on the real table returned {present_txn['Responses']!r}, expected the "
        f"seeded item"
    )

    code, msg, resp = _error(lambda: ddb.execute_transaction(TransactStatements=[{"Statement": select_absent}]))
    assert (code, msg) == _CANCELLED, (
        f"ExecuteTransaction naming a missing table gave {code!r}: {msg!r}, expected {_CANCELLED!r} "
        f"(not a top-level ResourceNotFoundException)"
    )
    reasons = resp.get("CancellationReasons")
    assert reasons == [{"Code": "ResourceNotFound", "Message": "Requested resource not found"}], (
        f"ExecuteTransaction's CancellationReasons were {reasons!r}"
    )


def _make_table(ctx) -> str:
    """A tagged on-demand table keyed pk (S) HASH, seeded with one item, deleted at cleanup."""
    ddb = ctx.client("dynamodb")
    name = ctx.unique_name("sim2real-ddb-execpresent-")
    ddb.create_table(
        TableName=name,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=name))
    ddb.get_waiter("table_exists").wait(TableName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    ddb.put_item(TableName=name, Item={"pk": {"S": "k1"}})
    return name


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
