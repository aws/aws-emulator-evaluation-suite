"""batch-execute-statement-select-missing-parameter-is-a-slot-error."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "batch-execute-statement-select-missing-parameter-is-a-slot-error"
GROUP = "partiql"
SERVICES = ["dynamodb"]

_ERROR = {"Code": "ValidationError", "Message": "Number of parameters in request and statement don't match."}


def _table(ctx) -> str:
    ddb = ctx.client("dynamodb")
    t = ctx.unique_name("sim2real-behav-")
    ddb.create_table(
        TableName=t,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=t))
    ddb.get_waiter("table_exists").wait(TableName=t, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    return t


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A BatchExecuteStatement SELECT whose placeholder has no matching Parameters entry
    fails only its own slot with a per-slot ValidationError, not a thrown exception, and a
    sibling SELECT with its parameter supplied still returns its item.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_BatchExecuteStatement.html
    """
    ddb = ctx.client("dynamodb")
    t = _table(ctx)
    good_item = {"pk": {"S": "sibling"}, "val": {"S": "present"}}
    ddb.put_item(TableName=t, Item=good_item)

    resp = ddb.batch_execute_statement(Statements=[
        {"Statement": f'SELECT * FROM "{t}" WHERE pk = ?', "ConsistentRead": True},
        {"Statement": f'SELECT * FROM "{t}" WHERE pk = ?', "Parameters": [{"S": "sibling"}], "ConsistentRead": True},
    ])
    responses = resp["Responses"]
    assert len(responses) == 2, f"expected 2 per-statement responses, got {len(responses)}: {responses!r}"
    bad, good = responses

    assert bad == {"Error": _ERROR}, (
        f"expected the slot with no Parameters entry to carry exactly {{'Error': {_ERROR!r}}}, got {bad!r}"
    )
    assert good == {"TableName": t, "Item": good_item}, (
        f"expected the sibling SELECT to carry its matched item, got {good!r}"
    )

    # Positive control: the identical statement text succeeds once its Parameters entry
    # is supplied, isolating the missing-placeholder value as the cause of the slot error.
    resp2 = ddb.batch_execute_statement(Statements=[
        {"Statement": f'SELECT * FROM "{t}" WHERE pk = ?', "Parameters": [{"S": "sibling"}], "ConsistentRead": True},
    ])
    fixed = resp2["Responses"]
    assert fixed == [{"TableName": t, "Item": good_item}], (
        f"expected supplying the parameter to make the statement succeed, got {fixed!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
