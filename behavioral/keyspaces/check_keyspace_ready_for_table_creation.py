"""keyspace-ready-for-table-creation."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "keyspace-ready-for-table-creation"
GROUP = "state-machine"
SERVICES = ["keyspaces"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A newly created keyspace transitions CREATING -> ACTIVE; CreateTable inside it eventually stops 404ing."""
    kc = ctx.client("keyspaces")
    ks_name = _kname(ctx, "sim2real_behav_ks")
    tbl_name = _kname(ctx, "sim2real_behav_tbl")

    kc.create_keyspace(keyspaceName=ks_name, tags=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: kc.delete_keyspace(keyspaceName=ks_name)))

    schema = {"allColumns": [{"name": "pk", "type": "text"}], "partitionKeys": [{"name": "pk"}]}
    from botocore.exceptions import ClientError
    deadline = time.monotonic() + 90.0
    created = False
    last_code = None
    while time.monotonic() < deadline:
        try:
            kc.create_table(
                keyspaceName=ks_name,
                tableName=tbl_name,
                schemaDefinition=schema,
                tags=[{"key": "sim2real", "value": CHECK}],
            )
            created = True
            break
        except ClientError as exc:
            last_code = exc.response["Error"]["Code"]
            if last_code != "ResourceNotFoundException":
                raise
            time.sleep(2.0)
    assert created, f"keyspace never became usable for CreateTable, last error: {last_code}"
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: kc.delete_table(keyspaceName=ks_name, tableName=tbl_name)))

    # Independent read at the destination: `created` only proves CreateTable itself returned
    # without raising, which is the mutating call's own response. GetTable is a different
    # operation and is the thing that actually shows the table now exists. A successful
    # CreateTable response does not mean GetTable sees it yet -- real AWS answers
    # ResourceNotFoundException ("unconfigured table") for a further beat after CreateTable
    # itself already stopped 404ing, so this read is bounded and retried on that same code.
    get_deadline = time.monotonic() + 60.0
    table = None
    get_last_code = None
    while time.monotonic() < get_deadline:
        try:
            table = kc.get_table(keyspaceName=ks_name, tableName=tbl_name)
            break
        except ClientError as exc:
            get_last_code = exc.response["Error"]["Code"]
            if get_last_code != "ResourceNotFoundException":
                raise
            time.sleep(2.0)
    assert table is not None, f"GetTable never saw the created table, last error: {get_last_code}"
    assert table["tableName"] == tbl_name, f"expected table {tbl_name!r}, got {table.get('tableName')!r}"
    assert table["status"] in ("CREATING", "ACTIVE"), f"unexpected table status right after create: {table.get('status')!r}"

    keyspaces = kc.list_keyspaces()["keyspaces"]
    assert ks_name in [k["keyspaceName"] for k in keyspaces], f"{ks_name!r} missing from list_keyspaces: {keyspaces}"


def _kname(ctx, prefix: str) -> str:
    return ctx.unique_name(prefix + "-").replace("-", "_")[:48]


def _ignore_not_found(fn) -> None:
    from botocore.exceptions import ClientError
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
