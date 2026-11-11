"""create-table-gsi-key-not-in-attribute-definitions-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-table-gsi-key-not-in-attribute-definitions-rejected"
GROUP = 'overly-permissive'
SERVICES = ['dynamodb']


def _error(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message) if a ClientError is raised. Raises
    if fn() unexpectedly succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded: {result!r}")


def _delete_table_if_exists(ddb, table_name):
    """Cleanup for a table the check expects never to exist: delete it if a target created it."""
    try:
        ddb.delete_table(TableName=table_name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


def _wait_table_active(ddb, table_name, timeout_s=60.0, interval_s=1.0):
    """Poll DescribeTable until TableStatus is ACTIVE (a transient 404 counts as not-yet)."""
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        try:
            status = ddb.describe_table(TableName=table_name)["Table"]["TableStatus"]
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
                raise
            status = "PENDING"
        if status == "ACTIVE":
            return status
        time.sleep(interval_s)
    raise AssertionError(f"table {table_name} never went ACTIVE in {timeout_s}s (last={status})")


def _hash_key_schema(key_name="pk", key_type="S"):
    """Return (KeySchema, AttributeDefinitions) for a hash-only table."""
    return (
        [{"AttributeName": key_name, "KeyType": "HASH"}],
        [{"AttributeName": key_name, "AttributeType": key_type}],
    )


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateTable with a GSI keyed on an attribute absent from AttributeDefinitions must be rejected."""
    ddb = ctx.client("dynamodb")

    # Positive control: the identical call shape, with the GSI key attribute correctly declared
    # in AttributeDefinitions, must succeed. Without this, "rejects this GSI" is indistinguishable
    # from "rejects every CreateTable with a GSI".
    good_table = ctx.unique_name("sim2real-behav-ddb-goodgsi-")
    good_attr_defs = [
        {"AttributeName": "pk", "AttributeType": "S"},
        {"AttributeName": "gsi_pk", "AttributeType": "S"},
    ]
    ddb.create_table(
        TableName=good_table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=good_attr_defs,
        BillingMode="PAY_PER_REQUEST",
        GlobalSecondaryIndexes=[
            {
                "IndexName": "gsi1",
                "KeySchema": [{"AttributeName": "gsi_pk", "KeyType": "HASH"}],
                "Projection": {"ProjectionType": "ALL"},
            }
        ],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=good_table))
    _wait_table_active(ddb, good_table)
    good_gsi_names = [
        g["IndexName"]
        for g in ddb.describe_table(TableName=good_table)["Table"].get(
            "GlobalSecondaryIndexes", []
        )
    ]
    assert "gsi1" in good_gsi_names, (
        f"positive control: CreateTable with a correctly-declared GSI key attribute did not "
        f"produce the index, got {good_gsi_names!r}"
    )

    table_name = ctx.unique_name("sim2real-behav-ddb-badgsi-")
    key_schema, attr_defs = _hash_key_schema("pk")
    # Registered up front so an unexpectedly-accepted CreateTable cannot leak a table.
    ctx.on_cleanup(lambda: _delete_table_if_exists(ddb, table_name))

    code, message = _error(
        lambda: ddb.create_table(
            TableName=table_name,
            KeySchema=key_schema,
            # 'gsi_pk' is deliberately NOT declared in AttributeDefinitions.
            AttributeDefinitions=attr_defs,
            BillingMode="PAY_PER_REQUEST",
            GlobalSecondaryIndexes=[
                {
                    "IndexName": "gsi1",
                    "KeySchema": [{"AttributeName": "gsi_pk", "KeyType": "HASH"}],
                    "Projection": {"ProjectionType": "ALL"},
                }
            ],
            Tags=[{"Key": "sim2real", "Value": CHECK}],
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code}"
    expected_msg = (
        "One or more parameter values were invalid: Some index key attributes are not defined "
        "in AttributeDefinitions. Keys: [gsi_pk], AttributeDefinitions: [pk]"
    )
    assert message == expected_msg, f"expected message {expected_msg!r}, got {message!r}"

    # The rejected CreateTable must not have created a table at all.
    not_created, not_created_msg = _error(lambda: ddb.describe_table(TableName=table_name))
    assert (
        not_created == "ResourceNotFoundException"
    ), f"rejected CreateTable must not create the table, got {not_created}"
    expected_nf = f"Requested resource not found: Table: {table_name} not found"
    assert not_created_msg == expected_nf, (
        f"expected message {expected_nf!r}, got {not_created_msg!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
