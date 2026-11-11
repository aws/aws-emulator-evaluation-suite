"""batch-delete-connection-per-entry-errors-and-valid-deletes-land."""
# BatchDeleteConnection is partially successful: naming two live connections and one absent
# name in a single call deletes both live ones and reports ONLY the absent name in the
# Errors map. Modelled shape: BatchDeleteConnectionResponse { Succeeded: NameStringList,
# Errors: ErrorByName } — a map keyed by connection name (glue-2017-03-31.json).
#
# The per-entry ErrorCode for a name that does not exist is InternalException, NOT
# EntityNotFoundException — unlike BatchDeleteTable's Errors[].ErrorDetail.ErrorCode, which does
# use EntityNotFoundException on GetTable. BatchDeleteConnection's own per-entry error is a
# generic InternalException carrying "Connection not found <name>" in ErrorMessage.
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "batch-delete-connection-per-entry-errors-and-valid-deletes-land"
GROUP = "connection"
SERVICES = ["glue"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """BatchDeleteConnection deletes the live entries and reports only the absent one, per name."""
    glue = ctx.client("glue")

    live_a = _create_connection(ctx, glue)
    live_b = _create_connection(ctx, glue)
    absent = ctx.unique_name("sim2real-behav-conn-")

    # Positive control: both live connections are readable before the batch, and the absent
    # name genuinely is not. Without this, "reports one error" cannot be told from "reports an
    # error for everything".
    for name in (live_a, live_b):
        conn = glue.get_connection(Name=name)["Connection"]
        assert conn["Name"] == name, (
            f"GetConnection({name}) returned Name={conn.get('Name')!r} before the batch"
        )
    pre, pre_message = _error_code(lambda: glue.get_connection(Name=absent),
                      f"GetConnection({absent}) before the batch")
    assert pre == "EntityNotFoundException", (
        f"GetConnection({absent}) answered {pre!r} before the batch, expected "
        f"'EntityNotFoundException': the third entry must be genuinely absent for the "
        f"per-entry error to mean anything"
    )
    assert pre_message == f"Connection with name {absent} in account {ctx.account} is not found", (
        f"expected the exact EntityNotFoundException message AWS returns, got {pre_message!r}"
    )

    resp = glue.batch_delete_connection(ConnectionNameList=[live_a, live_b, absent])

    succeeded = set(resp["Succeeded"])
    assert succeeded == {live_a, live_b}, (
        f"BatchDeleteConnection reported Succeeded={sorted(succeeded)}, expected exactly the "
        f"two live connections {sorted({live_a, live_b})}: a batch that succeeds for the "
        f"absent name too is not doing per-entry evaluation"
    )
    errors = resp["Errors"]
    assert set(errors) == {absent}, (
        f"BatchDeleteConnection reported Errors keyed by {sorted(errors)}, expected exactly "
        f"[{absent!r}]"
    )
    assert errors[absent]["ErrorCode"] == "InternalException", (
        f"the per-entry error for {absent!r} carried ErrorCode="
        f"{errors[absent]['ErrorCode']!r}, expected 'InternalException'. Full entry: "
        f"{errors[absent]!r}"
    )
    assert absent in errors[absent].get("ErrorMessage", ""), (
        f"the per-entry error for {absent!r} carried ErrorMessage="
        f"{errors[absent].get('ErrorMessage')!r}, expected it to name the absent connection"
    )

    # An independent read through a different operation proves both live
    # connections are really gone, not merely reported as deleted.
    for name in (live_a, live_b):
        code, message = _error_code(lambda n=name: glue.get_connection(Name=n),
                           f"GetConnection({name}) after the batch delete")
        assert code == "EntityNotFoundException", (
            f"GetConnection({name}) answered {code!r} after BatchDeleteConnection listed it "
            f"in Succeeded, expected 'EntityNotFoundException'"
        )
        assert message == f"Connection with name {name} in account {ctx.account} is not found", (
            f"expected the exact EntityNotFoundException message AWS returns, got {message!r}"
        )

    # A MUTATION on the dead id also fails, so the connection is unusable and not
    # merely hidden from the reader.
    mutate, mutate_message = _error_code(
        lambda: glue.update_connection(
            Name=live_a,
            ConnectionInput={
                "Name": live_a,
                "ConnectionType": "JDBC",
                "ConnectionProperties": {
                    "JDBC_CONNECTION_URL": "jdbc:mysql://example.com:3306/db",
                    "USERNAME": "admin",
                    "PASSWORD": "super-secret-password",
                },
            },
        ),
        f"UpdateConnection({live_a}) on a deleted connection",
    )
    assert mutate == "EntityNotFoundException", (
        f"UpdateConnection({live_a}) on the deleted connection answered {mutate!r}, expected "
        f"'EntityNotFoundException': a deleted connection must be unusable, not just unread"
    )
    assert mutate_message == f"Connection not found: {live_a}", (
        f"expected the exact EntityNotFoundException message AWS returns, got {mutate_message!r}"
    )

    # The identifier is reusable, which a target that merely tombstones the name
    # would fail.
    _create_connection(ctx, glue, name=live_a)
    reused = glue.get_connection(Name=live_a)["Connection"]
    assert reused["ConnectionType"] == "JDBC", (
        f"recreating the deleted name {live_a!r} produced ConnectionType="
        f"{reused.get('ConnectionType')!r}, expected 'JDBC': the name must be free for reuse "
        f"after a batch delete"
    )


def _create_connection(ctx, glue, *, name: str | None = None) -> str:
    """A JDBC connection needing no VPC and no reachable database; cleanup is an explicit delete."""
    conn = name or ctx.unique_name("sim2real-behav-conn-")
    _retry_transient(
        lambda: glue.create_connection(
            ConnectionInput={
                "Name": conn,
                "Description": CHECK,
                "ConnectionType": "JDBC",
                "ConnectionProperties": {
                    "JDBC_CONNECTION_URL": "jdbc:mysql://example.com:3306/db",
                    "USERNAME": "admin",
                    "PASSWORD": "super-secret-password",
                },
            },
        ),
        f"CreateConnection({conn})",
    )
    ctx.on_cleanup(lambda: _retry_delete(
        lambda: glue.delete_connection(ConnectionName=conn), f"glue connection {conn}"))
    return conn


def _error_code(fn, label: str) -> tuple[str, str]:
    """Return the ClientError code and message, RAISING on unexpected success so an over-permissive
    target shows as acceptance, not as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"]["Message"]
    raise AssertionError(f"{label} succeeded; it must be refused")


_TRANSIENT_CODES = ("ThrottlingException", "Throttling", "TooManyRequestsException",
                    "OperationTimeoutException", "ConcurrentModificationException",
                    "RequestLimitExceeded")


def _retry_transient(fn, label: str, *, timeout_s: float = 60.0) -> None:
    """Retry a mutating call bounded, for codes real Glue answers transiently under
    back-to-back catalog writes. Raises on timeout, never swallows into a false pass."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code not in _TRANSIENT_CODES or time.monotonic() >= deadline:
                raise
            time.sleep(3)


def _retry_delete(fn, label: str, *, timeout_s: float = 120.0) -> None:
    """Delete with a bounded retry, because ctx.on_cleanup SWALLOWS teardown exceptions: a
    throttled or dependency-blocked delete would leak silently while the check passes."""
    from botocore.exceptions import ClientError

    gone = ("EntityNotFoundException", "ResourceNotFoundException")
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code in gone:
                return
            if code not in _TRANSIENT_CODES or time.monotonic() >= deadline:
                raise RuntimeError(f"{label}: {code}: {err}") from err
            time.sleep(3)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
