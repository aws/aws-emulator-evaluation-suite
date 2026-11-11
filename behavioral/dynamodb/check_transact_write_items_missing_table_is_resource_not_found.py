"""transact-write-items-missing-table-is-resource-not-found."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "transact-write-items-missing-table-is-resource-not-found"
GROUP = "transactions"
SERVICES = ["dynamodb"]

_RNF = ("ResourceNotFoundException", "Requested resource not found")


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise
    return run_undo


def _wait_active(ddb, ctx, table):
    """Poll DescribeTable every 2 s until the table is ACTIVE."""
    deadline = time.monotonic() + max(0.0, (ctx.time_left() or 300.0) - 30.0)
    status = None
    while time.monotonic() < deadline:
        status = ddb.describe_table(TableName=table)["Table"]["TableStatus"]
        if status == "ACTIVE":
            return
        time.sleep(2)
    raise AssertionError(f"table {table} not ACTIVE before the deadline: {status!r}")


def _error(fn, code, message):
    """Call fn(); assert the ClientError carries exactly (code, message); an accepted call fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        assert err.get("Code") == code, f"expected {code!r}, got {err.get('Code')!r}: {err!r}"
        assert err.get("Message") == message, f"expected {message!r}, got {err.get('Message')!r}"
        return
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "plane:data", "dp:api")
def run(ctx) -> None:
    """A TransactWriteItems naming a table that does not exist, with no other defect, fails the
    whole call with ResourceNotFoundException and does not apply a sibling Put on a real table.
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddb-twirnf-")
    missing_table = ctx.unique_name("sim2real-behav-ddb-twirnf-missing-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=table), "ResourceNotFoundException"))
    _wait_active(ddb, ctx, table)

    # Positive control: a well-formed transaction against the real table is accepted and lands.
    ddb.transact_write_items(TransactItems=[
        {"Put": {"TableName": table, "Item": {"pk": {"S": "control"}}}}])
    control_got = ddb.get_item(TableName=table, Key={"pk": {"S": "control"}}, ConsistentRead=True).get("Item")
    assert control_got == {"pk": {"S": "control"}}, (
        f"positive control: expected the well-formed TransactWriteItems to land, got {control_got!r}"
    )

    # Break exactly one thing: a sibling Put addresses a table that was never created.
    sibling_key = {"pk": {"S": "sibling-should-not-write"}}
    _error(
        lambda: ddb.transact_write_items(TransactItems=[
            {"Put": {"TableName": missing_table, "Item": {"pk": {"S": "x"}}}},
            {"Put": {"TableName": table, "Item": sibling_key}},
        ]),
        *_RNF,
    )

    sibling_got = ddb.get_item(TableName=table, Key=sibling_key, ConsistentRead=True).get("Item")
    assert sibling_got is None, (
        f"a TransactWriteItems that failed with ResourceNotFoundException must not apply its "
        f"sibling Put; got {sibling_got!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
