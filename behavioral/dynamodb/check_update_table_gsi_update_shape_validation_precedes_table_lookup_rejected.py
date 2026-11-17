"""update-table-gsi-update-shape-validation-precedes-table-lookup-rejected."""
from __future__ import annotations

import time

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-table-gsi-update-shape-validation-precedes-table-lookup-rejected"
GROUP = "negative-classes"
SERVICES = ["dynamodb"]


def _teardown(undo, *not_found: str):
    """A cleanup running undo(); only the resource's own not-found codes mean it is gone."""
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise
    return run_undo


def _error(fn):
    """The (Code, Message) fn() raises. An unexpected success raises, naming what came back."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _wait_active(ddb, table, deadline_s=240):
    end = time.monotonic() + deadline_s
    desc = None
    while time.monotonic() < end:
        desc = ddb.describe_table(TableName=table)["Table"]
        if desc["TableStatus"] == "ACTIVE":
            return desc
        time.sleep(3)
    raise AssertionError(f"{table} never became ACTIVE within {deadline_s}s: {desc!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateTable folds a pattern-invalid name, null capacity members, a length-invalid name
    and a missing capacity bound into one ValidationException, and answers out-of-range GSI
    capacity values with ValidationException even against a table that does not exist.
    """
    ddb = ctx.client("dynamodb")
    lax = ctx.client("dynamodb", config=Config(parameter_validation=False))
    table = ctx.unique_name("sim2real-behav-ddb-gsishape-")
    ddb.create_table(
        TableName=table,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=table), "ResourceNotFoundException"))
    _wait_active(ddb, table)

    # Positive control: a well-formed UpdateTable call on this table is accepted and takes
    # effect, round-tripped back off before cleanup needs to delete the table.
    ddb.update_table(TableName=table, DeletionProtectionEnabled=True)
    desc = _wait_active(ddb, table)
    assert desc["DeletionProtectionEnabled"] is True, (
        f"the positive-control update left DeletionProtectionEnabled={desc['DeletionProtectionEnabled']!r}"
    )
    ddb.update_table(TableName=table, DeletionProtectionEnabled=False)
    desc = _wait_active(ddb, table)
    assert desc["DeletionProtectionEnabled"] is False, (
        f"turning deletion protection back off left DeletionProtectionEnabled={desc['DeletionProtectionEnabled']!r}"
    )

    # Break exactly one thing: two Update entries whose shape botocore would normally refuse
    # client-side -- a pattern-invalid name with null capacity members, and a length-invalid
    # name missing one capacity bound -- sent past client validation so AWS answers them.
    code, msg = _error(lambda: lax.update_table(
        TableName=table,
        GlobalSecondaryIndexUpdates=[
            {"Update": {
                "IndexName": "bad name!",
                "ProvisionedThroughput": {"ReadCapacityUnits": None, "WriteCapacityUnits": None},
            }},
            {"Update": {
                "IndexName": "cd",
                "ProvisionedThroughput": {"ReadCapacityUnits": 5},
            }},
        ],
    ))
    expected_fold = (
        "ValidationException",
        "5 validation errors detected: Value 'bad name!' at "
        "'globalSecondaryIndexUpdates.1.member.update.indexName' failed to satisfy constraint: "
        "Member must satisfy regular expression pattern: [a-zA-Z0-9_.-]+; Value null at "
        "'globalSecondaryIndexUpdates.1.member.update.provisionedThroughput.writeCapacityUnits' "
        "failed to satisfy constraint: Member must not be null; Value null at "
        "'globalSecondaryIndexUpdates.1.member.update.provisionedThroughput.readCapacityUnits' "
        "failed to satisfy constraint: Member must not be null; Value 'cd' at "
        "'globalSecondaryIndexUpdates.2.member.update.indexName' failed to satisfy constraint: "
        "Member must have length greater than or equal to 3; Value null at "
        "'globalSecondaryIndexUpdates.2.member.update.provisionedThroughput.writeCapacityUnits' "
        "failed to satisfy constraint: Member must not be null",
    )
    assert (code, msg) == expected_fold, (
        f"the two malformed Update entries gave {(code, msg)!r}, expected {expected_fold!r}"
    )

    # Break the other thing: a GSI update whose capacity values violate the model's own
    # minimum, aimed at a table that was never created. The shape violation is answered, not
    # the table's absence.
    absent_table = ctx.unique_name("sim2real-behav-ddb-gsishape-notable-")
    code, msg = _error(lambda: lax.update_table(
        TableName=absent_table,
        GlobalSecondaryIndexUpdates=[{"Update": {
            "IndexName": "whatever",
            "ProvisionedThroughput": {"ReadCapacityUnits": -1, "WriteCapacityUnits": 0},
        }}],
    ))
    expected_shape = (
        "ValidationException",
        "2 validation errors detected: Value '0' at "
        "'globalSecondaryIndexUpdates.1.member.update.provisionedThroughput.writeCapacityUnits' "
        "failed to satisfy constraint: Member must have value greater than or equal to 1; "
        "Value '-1' at "
        "'globalSecondaryIndexUpdates.1.member.update.provisionedThroughput.readCapacityUnits' "
        "failed to satisfy constraint: Member must have value greater than or equal to 1",
    )
    assert (code, msg) == expected_shape, (
        f"the out-of-range capacity against a nonexistent table gave {(code, msg)!r}, "
        f"expected {expected_shape!r}"
    )

    # Neither rejected call changed the real table.
    desc = ddb.describe_table(TableName=table)["Table"]
    assert desc.get("GlobalSecondaryIndexes") is None, (
        f"the table unexpectedly has GSIs {desc.get('GlobalSecondaryIndexes')!r}"
    )
    assert desc["DeletionProtectionEnabled"] is False, (
        f"the table's DeletionProtectionEnabled drifted to {desc['DeletionProtectionEnabled']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
