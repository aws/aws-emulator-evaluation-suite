"""table-create-active-transition."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "table-create-active-transition"
GROUP = "state-machine"
SERVICES = ["keyspaces"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateTable transitions Table.status from CREATING to ACTIVE, observable via GetTable."""
    kc = ctx.client("keyspaces")
    ks_name = _kname(ctx, "sim2real_behav_ks")
    tbl_name = _kname(ctx, "sim2real_behav_tbl")

    kc.create_keyspace(keyspaceName=ks_name, tags=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: kc.delete_keyspace(keyspaceName=ks_name)))

    schema = {
        "allColumns": [{"name": "pk", "type": "text"}, {"name": "val", "type": "text"}],
        "partitionKeys": [{"name": "pk"}],
    }
    _create_table_when_ready(ctx, kc, ks_name, tbl_name, schema, tags=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: kc.delete_table(keyspaceName=ks_name, tableName=tbl_name)))

    statuses_seen = []
    deadline = time.monotonic() + 180.0
    final_status = None
    from botocore.exceptions import ClientError
    while time.monotonic() < deadline:
        try:
            final_status = kc.get_table(keyspaceName=ks_name, tableName=tbl_name)["status"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
            time.sleep(2.0)
            continue
        statuses_seen.append(final_status)
        if final_status == "ACTIVE":
            break
        time.sleep(3.0)
    assert final_status == "ACTIVE", f"table never reached ACTIVE, last statuses observed: {statuses_seen[-5:]}"
    assert all(s in ("CREATING", "ACTIVE") for s in statuses_seen), (
        f"expected only CREATING/ACTIVE, observed: {statuses_seen}"
    )
    assert "CREATING" in statuses_seen, (
        f"never observed the table in CREATING before ACTIVE, observed: {statuses_seen}"
    )


def _kname(ctx, prefix: str) -> str:
    return ctx.unique_name(prefix + "-").replace("-", "_")[:48]


def _ignore_not_found(fn) -> None:
    from botocore.exceptions import ClientError
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _create_table_when_ready(ctx, kc, ks_name: str, tbl_name: str, schema: dict, timeout_s: float = 90.0, **kwargs) -> None:
    """CreateTable right after CreateKeyspace can transiently 404 until the keyspace is
    visible; retry only that specific transient condition."""
    from botocore.exceptions import ClientError
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            kc.create_table(keyspaceName=ks_name, tableName=tbl_name, schemaDefinition=schema, **kwargs)
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException" or time.monotonic() > deadline:
                raise
            time.sleep(2.0)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
