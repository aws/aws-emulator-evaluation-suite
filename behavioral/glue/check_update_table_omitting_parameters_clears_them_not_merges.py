"""update-table-omitting-parameters-clears-them-not-merges."""
# UpdateTable takes a complete TableInput and replaces the stored table with it, so keys the new
# TableInput omits (Parameters, Description, Owner) are cleared rather than merged forward. Glue
# may add parameters of its own on write (such as transient_lastDdlTime), so the assertion is a
# set difference against the target's own previously reported parameter set, never an equality to
# {}. UpdateTable archives the pre-update table as a new version: GetTableVersion for the version
# id reported before the update still returns the original Parameters. VersionId is a decimal
# string that UpdateTable advances by exactly one from the value reported at create time; no
# literal version number is pinned.
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "update-table-omitting-parameters-clears-them-not-merges"
GROUP = "table"
SERVICES = ["glue"]


@tags("axis:happy-path", "cap:c2", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateTable is a whole-object replace: omitted Parameters/Description are cleared, and the archived version keeps them."""
    glue = ctx.client("glue")

    database = ctx.unique_name("sim2real_behav_updtbl_").replace("-", "_")
    glue.create_database(DatabaseInput={"Name": database})
    ctx.on_cleanup(lambda: _retry_delete(lambda: glue.delete_database(Name=database),
                                         f"glue database {database}"))

    table = ctx.unique_name("sim2real_behav_tbl_").replace("-", "_")
    marker = ctx.unique_name("mk").lower()
    glue.create_table(
        DatabaseName=database,
        TableInput={
            "Name": table,
            "Description": "the original description",
            "Owner": "sim2real-original-owner",
            "StorageDescriptor": {
                "Columns": [{"Name": "col1", "Type": "string"}],
                "Location": "s3://example-bucket/original/",
            },
            "Parameters": {
                "classification": "csv",
                f"sim2real_{marker}": "must-not-survive-an-omitting-update",
                "sim2real": CHECK,
            },
        },
    )
    ctx.on_cleanup(lambda: _retry_delete(
        lambda: glue.delete_table(DatabaseName=database, Name=table),
        f"glue table {database}.{table}"))

    before = glue.get_table(DatabaseName=database, Name=table)["Table"]
    authored = {"classification", f"sim2real_{marker}", "sim2real"}
    before_params = before["Parameters"]
    assert authored <= set(before_params), (
        f"CreateTable did not store the authored parameters: GetTable reported "
        f"{sorted(before_params)}, which is missing {sorted(authored - set(before_params))}. "
        f"The rest of this check measures what an update does to them, so they must be there "
        f"first"
    )
    assert before["Description"] == "the original description", (
        f"Description came back as {before.get('Description')!r} at create time"
    )
    before_version = before["VersionId"]

    # The update: a complete TableInput that names the table and its storage, and omits
    # Parameters, Description and Owner entirely.
    glue.update_table(
        DatabaseName=database,
        TableInput={
            "Name": table,
            "StorageDescriptor": {
                "Columns": [{"Name": "col1", "Type": "string"}],
                "Location": "s3://example-bucket/updated/",
            },
        },
    )

    after = glue.get_table(DatabaseName=database, Name=table)["Table"]

    # The update landed at all — cheap guard against grading an update that did nothing.
    assert after["StorageDescriptor"]["Location"] == "s3://example-bucket/updated/", (
        f"UpdateTable did not take effect: Location is still "
        f"{after['StorageDescriptor']['Location']!r}"
    )

    # THE assertion: an exact set difference against the target's own reported prior state.
    # `.get("Parameters", {})` is legitimate here because it feeds an emptiness assertion —
    # the empty default is the outcome the check is testing for, not a value that hides a
    # failure.
    survivors = authored & set(after.get("Parameters", {}))
    assert not survivors, (
        f"UpdateTable merged instead of replacing: the parameters {sorted(survivors)} "
        f"survived a TableInput that omitted Parameters entirely. After the update GetTable "
        f"reports {sorted(after.get('Parameters', {}))}; the authored set was "
        f"{sorted(authored)}"
    )
    assert "Description" not in after, (
        f"UpdateTable kept Description={after.get('Description')!r} after a TableInput that "
        f"omitted it; a whole-object replace must clear it"
    )
    assert "Owner" not in after, (
        f"UpdateTable kept Owner={after.get('Owner')!r} after a TableInput that omitted it; "
        f"a whole-object replace must clear it"
    )

    # The independent read at a different destination: the archived version, reached
    # through GetTableVersion rather than GetTable, must still carry the original parameters.
    # This is what turns "the parameters are gone" into "the parameters were replaced": a
    # target that never stored them fails here, and a target that merged fails above.
    archived = glue.get_table_version(
        DatabaseName=database, TableName=table, VersionId=before_version
    )["TableVersion"]["Table"]
    missing = authored - set(archived["Parameters"])
    assert not missing, (
        f"GetTableVersion(VersionId={before_version!r}) is missing {sorted(missing)} from "
        f"Parameters={sorted(archived['Parameters'])}; the archived version must preserve the "
        f"pre-update state that the live table just lost"
    )
    assert archived["Parameters"]["classification"] == "csv", (
        f"the archived version reports classification="
        f"{archived['Parameters']['classification']!r}, expected 'csv'"
    )
    assert archived["StorageDescriptor"]["Location"] == "s3://example-bucket/original/", (
        f"the archived version points at "
        f"{archived['StorageDescriptor']['Location']!r}, expected the pre-update "
        f"s3://example-bucket/original/"
    )

    # The version id advanced by exactly one from whatever the target reported at create time.
    # No literal is pinned — the expected value is derived from the target's own answer.
    assert int(after["VersionId"]) == int(before_version) + 1, (
        f"VersionId went {before_version!r} -> {after['VersionId']!r}; one UpdateTable must "
        f"advance it by exactly 1"
    )


def _retry_delete(fn, label: str, *, timeout_s: float = 120.0) -> None:
    """Delete with a bounded retry, because ctx.on_cleanup SWALLOWS teardown exceptions: a
    throttled or dependency-blocked delete would leak silently while the check passes."""
    from botocore.exceptions import ClientError

    gone = ("EntityNotFoundException", "ResourceNotFoundException")
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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
