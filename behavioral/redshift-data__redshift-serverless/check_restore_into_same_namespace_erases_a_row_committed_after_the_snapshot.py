"""restore-into-same-namespace-erases-a-row-committed-after-the-snapshot."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "restore-into-same-namespace-erases-a-row-committed-after-the-snapshot"
GROUP = "snapshot-lifecycle"
SERVICES = ["redshift-data", "redshift-serverless"]

_IDENTITY_FIELDS = (
    "snapshotName", "snapshotArn", "namespaceName", "namespaceArn",
    "status", "snapshotCreateTime", "ownerAccount", "snapshotRetentionPeriod",
)


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetSnapshot and ListSnapshots describe a snapshot identically; RestoreFromSnapshot back
    into the SAME namespace erases a row a later statement committed after the snapshot, and
    once DeleteSnapshot finishes neither read shows the snapshot any more."""
    rss = ctx.client("redshift-serverless")
    rd = ctx.client("redshift-data")

    ns = ctx.unique_name("sim2real-rdns-")
    wg = ctx.unique_name("sim2real-rdwg-")
    table = ctx.unique_name("sim2real_rdtbl_").replace("-", "_")

    rss.create_namespace(namespaceName=ns, dbName="dev",
                          tags=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(lambda: _delete_namespace(rss, ns))

    rss.create_workgroup(workgroupName=wg, namespaceName=ns, baseCapacity=8,
                          publiclyAccessible=False,
                          tags=[{"key": "sim2real", "value": CHECK}],
                          subnetIds=ctx.network().subnet_ids)
    ctx.on_cleanup(lambda: _delete_workgroup(rss, wg))
    _until(lambda: _workgroup_status(rss, wg), lambda s: s == "AVAILABLE",
           timeout_s=900, interval_s=10, label=f"workgroup {wg} AVAILABLE")

    _run_sql(rd, wg, f"CREATE TABLE {table} (id INT, label VARCHAR(16))")
    _run_sql(rd, wg, f"INSERT INTO {table} VALUES (1, 'kept')")
    before_snapshot = _table_rows(rd, wg, table)
    assert before_snapshot == [(1, "kept")], (
        f"the row committed before the snapshot did not read back: {before_snapshot!r}")

    snapshot = ctx.unique_name("sim2real-rdsnap-")
    rss.create_snapshot(namespaceName=ns, snapshotName=snapshot, retentionPeriod=1,
                         tags=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(lambda: _delete_snapshot(rss, snapshot))
    via_get = _until(lambda: _get_snapshot(rss, snapshot),
                      lambda s: s is not None and s["status"] == "AVAILABLE",
                      timeout_s=900, interval_s=15, label=f"snapshot {snapshot} AVAILABLE")

    via_list = _list_snapshot(rss, ns, snapshot)
    assert via_list is not None, (
        f"ListSnapshots for namespace {ns!r} did not carry {snapshot!r}: saw nothing matching")
    for field in _IDENTITY_FIELDS:
        assert via_get[field] == via_list[field], (
            f"GetSnapshot.{field} = {via_get[field]!r} but ListSnapshots.{field} = "
            f"{via_list[field]!r} for the same snapshot {snapshot!r}")

    _run_sql(rd, wg, f"INSERT INTO {table} VALUES (2, 'dropped')")
    after_insert = _table_rows(rd, wg, table)
    assert after_insert == [(1, "kept"), (2, "dropped")], (
        f"the row committed after the snapshot did not land before the restore: {after_insert!r}")

    restored = _retry_while_settling(
        lambda: rss.restore_from_snapshot(namespaceName=ns, workgroupName=wg,
                                           snapshotName=snapshot),
        timeout_s=900, interval_s=15, label=f"RestoreFromSnapshot {ns}/{wg}")
    assert restored["snapshotName"] == snapshot, (
        f"RestoreFromSnapshot echoed snapshotName {restored['snapshotName']!r}, "
        f"expected {snapshot!r}")
    assert restored["namespace"]["namespaceName"] == ns, (
        f"RestoreFromSnapshot landed in namespace {restored['namespace']['namespaceName']!r}, "
        f"expected the SAME namespace {ns!r}")

    _until(lambda: _namespace_status(rss, ns), lambda s: s == "AVAILABLE",
           timeout_s=600, interval_s=10, label=f"namespace {ns} AVAILABLE after restore")
    _until(lambda: _workgroup_status(rss, wg), lambda s: s == "AVAILABLE",
           timeout_s=900, interval_s=10, label=f"workgroup {wg} AVAILABLE after restore")

    after_restore = _table_rows(rd, wg, table)
    assert after_restore == [(1, "kept")], (
        f"after an in-place restore to the pre-insert snapshot the table held {after_restore!r}, "
        f"expected only the row committed before the snapshot")

    _retry_while_settling(lambda: rss.delete_snapshot(snapshotName=snapshot),
                           timeout_s=900, interval_s=15, label=f"DeleteSnapshot {snapshot}")
    _until(lambda: _get_snapshot(rss, snapshot), lambda s: s is None,
           timeout_s=600, interval_s=10, label=f"snapshot {snapshot} gone from GetSnapshot")

    code, message = _client_error(lambda: rss.get_snapshot(snapshotName=snapshot))
    assert code == "ResourceNotFoundException", (
        f"GetSnapshot on the deleted snapshot returned {code!r}, expected "
        f"ResourceNotFoundException: {message!r}")
    expected_message = (
        f"The snapshot {snapshot} was not found. Please Check whether the snapshot "
        f"exists and is owned by or shared with account {ctx.account}.")
    assert message == expected_message, (
        f"expected the message {expected_message!r}, got {message!r}")

    still_listed = _list_snapshot(rss, ns, snapshot)
    assert still_listed is None, (
        f"ListSnapshots for namespace {ns!r} still carries the deleted snapshot: {still_listed!r}")


# ===== self-contained helpers =====


def _until(probe, predicate, *, timeout_s, interval_s, label):
    """Poll ``probe`` until ``predicate`` holds; raise naming the last observed value."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{label} not reached within {timeout_s}s (last observed {last!r})")


def _client_error(fn):
    """(Error.Code, Error.Message) of the ClientError ``fn`` raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it SUCCEEDED: {result!r}")


def _not_found_as_none(fn, **kwargs):
    try:
        return fn(**kwargs)
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFoundException":
            return None
        raise


def _workgroup_status(rss, wg):
    r = _not_found_as_none(rss.get_workgroup, workgroupName=wg)
    return None if r is None else r["workgroup"]["status"]


def _namespace_status(rss, ns):
    r = _not_found_as_none(rss.get_namespace, namespaceName=ns)
    return None if r is None else r["namespace"]["status"]


def _get_snapshot(rss, name):
    r = _not_found_as_none(rss.get_snapshot, snapshotName=name)
    return None if r is None else r["snapshot"]


def _list_snapshot(rss, namespace, name):
    """The ListSnapshots entry named ``name`` for ``namespace``, or None if absent."""
    paginator = rss.get_paginator("list_snapshots")
    for page in paginator.paginate(namespaceName=namespace):
        for snap in page["snapshots"]:
            if snap["snapshotName"] == name:
                return snap
    return None


def _retry_while_settling(call, *, timeout_s, interval_s, label):
    """Retry ``call`` through ConflictException (the resource still settling a prior op)."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return call()
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ConflictException" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)
    raise AssertionError(f"{label} never settled within {timeout_s}s")


def _delete_workgroup(rss, wg):
    _drain_delete(lambda: rss.delete_workgroup(workgroupName=wg),
                  lambda: _workgroup_status(rss, wg), f"workgroup {wg}")


def _delete_namespace(rss, ns):
    _drain_delete(lambda: rss.delete_namespace(namespaceName=ns),
                  lambda: _namespace_status(rss, ns), f"namespace {ns}")


def _delete_snapshot(rss, name):
    _drain_delete(lambda: rss.delete_snapshot(snapshotName=name),
                  lambda: _get_snapshot(rss, name), f"snapshot {name}")


def _drain_delete(call, probe, label, *, timeout_s=900, interval_s=15):
    """Issue ``call`` until AWS accepts it, then wait for ``probe`` to report the resource gone."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            call()
            break
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code != "ConflictException" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)
    while time.monotonic() < deadline:
        if probe() is None:
            return
        time.sleep(interval_s)
    raise AssertionError(f"{label}: still present after {timeout_s}s")


def _run_sql(rd, workgroup, sql, *, timeout_s=300):
    """Run ``sql`` on ``workgroup``/dev to a terminal state; raise if it did not FINISH."""
    sid = rd.execute_statement(WorkgroupName=workgroup, Database="dev", Sql=sql)["Id"]
    final = _until(lambda: rd.describe_statement(Id=sid),
                   lambda d: d["Status"] in ("FINISHED", "FAILED", "ABORTED"),
                   timeout_s=timeout_s, interval_s=3, label=f"statement {sid} terminal")
    assert final["Status"] == "FINISHED", (
        f"{sql!r} ended {final['Status']!r}: {final.get('Error')!r}")
    return sid


def _table_rows(rd, workgroup, table):
    sid = _run_sql(rd, workgroup, f"SELECT id, label FROM {table} ORDER BY id")
    result = rd.get_statement_result(Id=sid)
    return [(r[0].get("longValue"), r[1].get("stringValue")) for r in result["Records"]]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
