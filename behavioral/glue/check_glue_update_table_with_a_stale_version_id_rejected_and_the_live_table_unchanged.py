"""glue-update-table-with-a-stale-version-id-rejected-and-the-live-table-unchanged."""
from __future__ import annotations

import time
from typing import Any, Callable

from behavioral_harness import tags

CHECK = "glue-update-table-with-a-stale-version-id-rejected-and-the-live-table-unchanged"
GROUP = 'catalog-concurrency'
SERVICES = ['glue']


@tags(
    "axis:rejection",
    "concern:negative-classes",
    "concern:representation",
    "cap:c1",
    "plane:control",
)
def run(ctx) -> None:
    """UpdateTable with a stale VersionId fails with ConcurrentModificationException and leaves
    the live table, its version pointer, and its version history without the loser's write.
    """
    glue = ctx.client("glue")

    database = ctx.unique_name("sim2real_behav_gluedb_").replace("-", "_")
    glue.create_database(DatabaseInput={"Name": database})
    ctx.on_cleanup(lambda: _retry_delete(lambda: glue.delete_database(Name=database),
                                         f"glue database {database}"))

    table = ctx.unique_name("sim2real_behav_gluetbl_").replace("-", "_")
    location = f"s3://sim2real-behav-glue-nonexistent/{table}/"
    glue.create_table(DatabaseName=database,
                      TableInput=_table_input(table, "revision-0", location))
    ctx.on_cleanup(lambda: _retry_delete(
        lambda: glue.delete_table(DatabaseName=database, Name=table),
        f"glue table {database}.{table}"))

    created_version = glue.get_table(DatabaseName=database, Name=table)["Table"]["VersionId"]

    # The winning writer advances the table off the version the loser is holding.
    glue.update_table(DatabaseName=database, VersionId=created_version,
                      TableInput=_table_input(table, "revision-1", location))
    winner = glue.get_table(DatabaseName=database, Name=table)["Table"]
    winning_version = winner["VersionId"]

    # Real AWS returns ConcurrentModificationException here, not the modelled
    # VersionMismatchException.
    stale_description = "stale-loser-must-not-land"
    code, message = _error(lambda: glue.update_table(
        DatabaseName=database, VersionId=created_version,
        TableInput=_table_input(table, stale_description, location)))

    after_reject = glue.get_table(DatabaseName=database, Name=table)["Table"]

    # Positive control: the same call with the CURRENT VersionId applies.
    glue.update_table(DatabaseName=database, VersionId=winning_version,
                      TableInput=_table_input(table, "revision-2", location))
    final = glue.get_table(DatabaseName=database, Name=table)["Table"]

    versions = []
    for page in glue.get_paginator("get_table_versions").paginate(DatabaseName=database,
                                                                TableName=table):
        versions.extend(page["TableVersions"])
    archived = {v["VersionId"]: v["Table"].get("Description") for v in versions}

    assert code == "ConcurrentModificationException", (
        f"expected ConcurrentModificationException for a stale VersionId, got {code!r}"
    )
    expected = "Update table failed due to concurrent modifications."
    assert message == expected, f"expected message {expected!r}, got {message!r}"
    assert after_reject.get("Description") == "revision-1", (
        f"the live description after the rejected update is "
        f"{after_reject.get('Description')!r}, expected the winning writer's 'revision-1'"
    )
    assert after_reject["VersionId"] == winning_version, (
        f"the version pointer moved from {winning_version!r} to "
        f"{after_reject['VersionId']!r} on an update that was rejected"
    )
    assert stale_description not in archived.values(), (
        f"the rejected writer's description survives in the version history: {archived!r}"
    )
    assert final.get("Description") == "revision-2", (
        f"the positive control's update did not apply; the live description is "
        f"{final.get('Description')!r}"
    )
    assert final["VersionId"] != winning_version, (
        f"the accepted update left the version at {final['VersionId']!r}, so the pointer "
        f"does not advance on success either and the rejection proved nothing"
    )
    assert sorted(archived, key=int) == sorted(
        {created_version, winning_version, final["VersionId"]}, key=int), (
        f"the version history is {sorted(archived, key=int)!r}, expected exactly the three "
        f"versions the two accepted writes and the create produced"
    )


def _table_input(name: str, description: str, location: str) -> dict:
    return {
        "Name": name,
        "Description": description,
        "StorageDescriptor": {"Columns": [{"Name": "id", "Type": "bigint"}],
                              "Location": location},
    }


def _error(fn: Callable[[], Any]) -> tuple[str, str]:
    """Return the AWS error (code, message), or raise if the call unexpectedly succeeds."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError("the call succeeded; real AWS rejects it")


def _retry_delete(fn: Callable[[], Any], label: str, *, timeout_s: float = 120.0) -> None:
    """Delete with a bounded retry, so a throttled or dependency-blocked delete cannot leak
    silently (ctx.on_cleanup swallows teardown exceptions)."""
    from botocore.exceptions import ClientError

    gone = ("EntityNotFoundException", "NoSuchEntity", "ResourceNotFoundException")
    transient = ("ThrottlingException", "Throttling", "TooManyRequestsException",
                 "OperationTimeoutException", "ConcurrentModificationException",
                 "RequestLimitExceeded")
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code in gone:
                return
            if code not in transient or time.monotonic() >= deadline:
                raise RuntimeError(f"{label}: {code}: {err}") from err
            time.sleep(3)
        except Exception as exc:  # noqa: BLE001 - re-raised
            raise RuntimeError(f"{label}: {type(exc).__name__}: {exc}") from exc


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
