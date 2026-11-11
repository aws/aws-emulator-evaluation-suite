"""create-table-invalid-key-schema-fails."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-table-invalid-key-schema-fails"
GROUP = 'table_lifecycle'
SERVICES = ['dynamodb']


def _error(fn):
    """Call fn() and return the (Code, Message) of the ClientError it raises; an accepted call
    is itself a failure."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded: {result!r}")


def _table_names(ddb):
    """Every table name in the region, read through all ListTables pages."""
    names = []
    for page in ddb.get_paginator("list_tables").paginate():
        names.extend(page["TableNames"])
    return names


def _delete_table_if_exists(ddb, table_name):
    """Cleanup for a table the check expects never to exist: delete it if a target created it."""
    try:
        ddb.delete_table(TableName=table_name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateTable fails with ValidationException and the exact message when a key attribute has
    no AttributeDefinitions entry, creating no table; the same table with both keys defined succeeds."""
    ddb = ctx.client("dynamodb")

    control_name = ctx.unique_name("sim2real-behav-ddb-badkey-control-")
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=control_name))
    ddb.create_table(
        TableName=control_name,
        KeySchema=[
            {"AttributeName": "pk", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
        ],
        BillingMode="PAY_PER_REQUEST",
    )
    ddb.get_waiter("table_exists").wait(TableName=control_name, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    control_names = _table_names(ddb)
    assert control_name in control_names, (
        f"positive control: expected {control_name} to exist after a valid composite-key "
        f"CreateTable, absent from the {len(control_names)} listed tables"
    )

    table_name = ctx.unique_name("sim2real-behav-ddb-badkey-")
    # Registered up front so an unexpectedly-accepted CreateTable cannot leak a table.
    ctx.on_cleanup(lambda: _delete_table_if_exists(ddb, table_name))

    def bad_create():
        ddb.create_table(
            TableName=table_name,
            KeySchema=[
                {"AttributeName": "pk", "KeyType": "HASH"},
                {"AttributeName": "sk", "KeyType": "RANGE"},
            ],
            # "sk" is referenced by KeySchema but missing from AttributeDefinitions.
            AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
            BillingMode="PAY_PER_REQUEST",
        )

    code, message = _error(bad_create)
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    expected_msg = "Invalid KeySchema: Some index key attribute have no definition"
    assert message == expected_msg, f"expected message {expected_msg!r}, got {message!r}"
    names = _table_names(ddb)
    assert table_name not in names, (
        f"rejected CreateTable must not create {table_name}, yet ListTables lists it"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
