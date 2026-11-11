"""ddbctl-table-refuses-changes-while-creating-and-deleting."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "ddbctl-table-refuses-changes-while-creating-and-deleting"
GROUP = "state-machine"
SERVICES = ["dynamodb"]

#: The code ``_outcome`` reports for a call the target accepted.
_ACCEPTED = "<accepted>"

#: Fresh tables tried before the check gives up on observing a window it needs.
_ATTEMPTS = 5
#: Wall bound on all attempts; the runner's remaining time bounds it further.
_DEADLINE_S = 240.0
_TAGS = [{"Key": "sim2real", "Value": CHECK}]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A CREATING table refuses CreateBackup and UpdateContinuousBackups with TableNotFoundException and
    UpdateTable and DeleteTable with ResourceInUseException (being created); a DELETING table still
    describes as DELETING and refuses a second DeleteTable with ResourceInUseException (being deleted)."""
    ddb = ctx.client("dynamodb")
    deadline = time.monotonic() + _bound(ctx, _DEADLINE_S)
    creating = {
        "CreateBackup": lambda t: (
            _on_success(ctx, ddb.create_backup(TableName=t, BackupName=f"{t}-early"))
        ),
        "UpdateContinuousBackups": lambda t: ddb.update_continuous_backups(
            TableName=t, PointInTimeRecoverySpecification={"PointInTimeRecoveryEnabled": True}),
        "UpdateTable": lambda t: ddb.update_table(
            TableName=t, BillingMode="PROVISIONED",
            ProvisionedThroughput={"ReadCapacityUnits": 1, "WriteCapacityUnits": 1}),
        "DeleteTable": lambda t: ddb.delete_table(TableName=t),
    }
    creating_refusal = {
        "CreateBackup": ("TableNotFoundException", "Table not found: {t}"),
        "UpdateContinuousBackups": ("TableNotFoundException", "Table not found: {t}"),
        "UpdateTable": ("ResourceInUseException",
                        "Attempt to change a resource which is still in use: Table is being created: {t}"),
        "DeleteTable": ("ResourceInUseException",
                        "Attempt to change a resource which is still in use: Table is being created: {t}"),
    }
    pending_creating = list(creating)
    pending_deleting = ["DescribeTable", "DeleteTable"]
    tried = []
    for _ in range(_ATTEMPTS):
        if (not pending_creating and not pending_deleting) or time.monotonic() >= deadline:
            break
        table = ctx.unique_name("sim2real-ddbctl-tsm-")
        created = ddb.create_table(
            TableName=table, BillingMode="PAY_PER_REQUEST", Tags=_TAGS,
            AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
            KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        )["TableDescription"]
        ctx.on_cleanup(lambda t=table: _drop(ddb, t))
        assert created["TableStatus"] == "CREATING", (
            f"CreateTable answered TableStatus {created['TableStatus']!r}, expected 'CREATING'"
        )
        for op in list(pending_creating):
            if _status(ddb, table) != "CREATING":
                tried.append(f"{table}: left CREATING before {op}")
                break
            code, message = _outcome(lambda: creating[op](table))
            want_code, want_message = creating_refusal[op]
            want_message = want_message.format(t=table)
            if (code, message) == (want_code, want_message):
                pending_creating.remove(op)
                continue
            still = _status(ddb, table)
            assert still != "CREATING", (
                f"{op} on a table that stayed CREATING answered {code!r} {message!r}, expected "
                f"{want_code!r} {want_message!r}"
            )
            tried.append(f"{table}: {op} answered {code!r} after the table left CREATING ({still!r})")
            break
        if not pending_deleting or _status(ddb, table) in (None, "DELETING"):
            continue
        _active(ddb, table)
        deleted = ddb.delete_table(TableName=table)["TableDescription"]
        assert deleted["TableStatus"] == "DELETING", (
            f"DeleteTable on an ACTIVE table answered {deleted['TableStatus']!r}, expected 'DELETING'"
        )
        if "DescribeTable" in pending_deleting:
            status = _status(ddb, table)
            if status is None:
                tried.append(f"{table}: gone before DescribeTable read it DELETING")
                continue
            assert status == "DELETING", f"DescribeTable on a deleted table reported {status!r}"
            pending_deleting.remove("DescribeTable")
        code, message = _outcome(lambda: ddb.delete_table(TableName=table))
        want = ("ResourceInUseException",
                f"Attempt to change a resource which is still in use: Table is being deleted: {table}")
        if (code, message) == want:
            pending_deleting.remove("DeleteTable")
            continue
        assert code != _ACCEPTED, "a second DeleteTable on a DELETING table was accepted"
        assert (code, message) == ("ResourceNotFoundException",
                                   f"Requested resource not found: Table: {table} not found"), (
            f"a second DeleteTable on a DELETING table answered {code!r} {message!r}, expected {want!r}"
        )
        tried.append(f"{table}: gone before the second DeleteTable")
    assert not pending_creating and not pending_deleting, (
        f"never observed the refusal of {pending_creating} while CREATING and {pending_deleting} "
        f"while DELETING in {_ATTEMPTS} fresh tables: {tried!r}"
    )


def _on_success(ctx, resp: dict) -> dict:
    """A backup the target accepted is deleted at teardown."""
    arn = resp["BackupDetails"]["BackupArn"]
    ddb = ctx.client("dynamodb")

    def _delete_backup() -> None:
        try:
            ddb.delete_backup(BackupArn=arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "BackupNotFoundException":
                raise

    ctx.on_cleanup(_delete_backup)
    return resp


def _outcome(fn) -> tuple[str, str | None]:
    """(code, message) of the refusal ``fn`` raises, or (_ACCEPTED, repr of the answer) when the
    target accepts the call."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    return _ACCEPTED, repr(result)


def _status(ddb, table: str) -> str | None:
    try:
        return ddb.describe_table(TableName=table)["Table"]["TableStatus"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFoundException":
            return None
        raise


def _active(ddb, table: str) -> None:
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 90})


def _bound(ctx, cap_s: float) -> float:
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - min(60.0, left / 4)))


def _drop(ddb, table: str) -> None:
    """Delete the table once it settles; already gone or already DELETING counts as deleted."""
    status = _status(ddb, table)
    if status in (None, "DELETING"):
        return
    if status != "ACTIVE":
        _active(ddb, table)
    try:
        ddb.delete_table(TableName=table)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
