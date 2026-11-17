"""describe-table-after-delete-table-reads-deleting-until-not-found."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-table-after-delete-table-reads-deleting-until-not-found"
GROUP = "lifecycle"
SERVICES = ["dynamodb"]

_KEY = {
    "AttributeDefinitions": [{"AttributeName": "pk", "AttributeType": "S"}],
    "KeySchema": [{"AttributeName": "pk", "KeyType": "HASH"}],
}


def _wait_cap(ctx, cap_s: float) -> float:
    """cap_s, shortened when the runner stops the check sooner, keeping 5 s for the failure."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _drop_table(ddb, name: str):
    """A cleanup deleting the table, backing off while a create or tag update holds it; a failure raises."""

    def status() -> str:
        try:
            return ddb.describe_table(TableName=name)["Table"]["TableStatus"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
            return "GONE"

    def undo() -> None:
        for attempt in range(8):
            # A table just created can still read not-found, so GONE still sends the delete.
            if status() == "DELETING":
                return
            try:
                ddb.delete_table(TableName=name)
                return
            except ClientError as exc:
                code = exc.response["Error"]["Code"]
                if code == "ResourceNotFoundException":
                    return
                if code != "ResourceInUseException" or attempt == 7:
                    raise
            time.sleep(min(3 * 2 ** attempt, 60))

    return undo


def _new_table(ctx, ddb, name: str, **params) -> dict:
    """CreateTable, its delete registered at once, then DescribeTable polled to ACTIVE."""
    ddb.create_table(TableName=name, **params)
    ctx.on_cleanup(_drop_table(ddb, name))
    deadline = time.monotonic() + _wait_cap(ctx, 240.0)
    while True:
        try:
            table = ddb.describe_table(TableName=name)["Table"]
        except ClientError as exc:
            # DescribeTable can read not-found for a moment after CreateTable.
            if exc.response["Error"]["Code"] != "ResourceNotFoundException" or time.monotonic() >= deadline:
                raise
            table = {"TableStatus": "CREATING"}
        if table["TableStatus"] == "ACTIVE" or time.monotonic() >= deadline:
            break
        time.sleep(2)
    assert table["TableStatus"] == "ACTIVE", f"table {name} settled at {table['TableStatus']!r}"
    return table


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteTable answers DELETING, any DescribeTable that still finds the table reports DELETING,
    and the reads end in ResourceNotFoundException with the exact message; a delete seen at once is
    correct, so no DELETING read is required.
    """
    ddb = ctx.client("dynamodb")
    name = ctx.unique_name("sim2real-dtdr-")
    _new_table(ctx, ddb, name, BillingMode="PAY_PER_REQUEST", Tags=[{"Key": "sim2real", "Value": CHECK}], **_KEY)

    answered = ddb.delete_table(TableName=name)["TableDescription"]["TableStatus"]
    assert answered == "DELETING", f"DeleteTable answered TableStatus={answered!r}"
    deadline = time.monotonic() + _wait_cap(ctx, 180.0)
    seen = []
    while True:
        try:
            status = ddb.describe_table(TableName=name)["Table"]["TableStatus"]
        except ClientError as exc:
            err = exc.response["Error"]
            break
        seen.append(status)
        assert status == "DELETING", f"DescribeTable after DeleteTable reported {status!r}; reads so far {seen!r}"
        assert time.monotonic() < deadline, f"the table was still DELETING after {len(seen)} reads"
        time.sleep(2)

    expected = ("ResourceNotFoundException", f"Requested resource not found: Table: {name} not found")
    assert (err["Code"], err["Message"]) == expected, f"the deleted table read {(err['Code'], err['Message'])!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
