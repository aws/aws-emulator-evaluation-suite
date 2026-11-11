"""snapshot-restores-into-new-namespace-with-data."""
from __future__ import annotations

import time

from behavioral_harness import tags


CHECK = "snapshot-restores-into-new-namespace-with-data"
GROUP = "data-plane"
SERVICES = ["redshift-data", "redshift-serverless"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Redshift Serverless snapshot carries the namespace's committed rows, and
    RestoreFromSnapshot lands them in a DIFFERENT namespace, readable through its workgroup.
    """
    rss = ctx.client("redshift-serverless")
    rd = ctx.client("redshift-data")
    table = ctx.unique_name("sim2real_behav_t_").replace("-", "_")
    rows = [(1, "alice"), (2, "bob"), (3, "carol")]

    src_ns, src_wg, src_id = _provision(ctx, rss, "src")
    dst_ns, dst_wg, dst_id = _provision(ctx, rss, "dst")
    # Both are created before either AVAILABLE wait so the two provisioning clocks overlap.
    assert src_id != dst_id, f"the two namespaces share an id: {src_id!r}"

    _poll_until(lambda: _workgroup_status(rss, src_wg), lambda s: s == "AVAILABLE",
                timeout_s=900, interval_s=10, what=f"workgroup {src_wg} AVAILABLE")
    _poll_until(lambda: _workgroup_status(rss, dst_wg), lambda s: s == "AVAILABLE",
                timeout_s=900, interval_s=10, what=f"workgroup {dst_wg} AVAILABLE")

    # Commit real rows into the source namespace, and prove they are there before snapshotting.
    _execute_and_wait(rd, src_wg, f"CREATE TABLE {table} (id INT, name VARCHAR(16))")
    values = ", ".join(f"({i}, '{n}')" for i, n in rows)
    _execute_and_wait(rd, src_wg, f"INSERT INTO {table} VALUES {values}")
    assert _select_rows(rd, src_wg, table) == rows, "the source namespace did not commit the rows"

    snapshot = ctx.unique_name("sim2real-behav-rssnap-")
    rss.create_snapshot(namespaceName=src_ns, snapshotName=snapshot, retentionPeriod=1,
                        tags=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(lambda: _delete_snapshot(rss, snapshot))
    snap = _poll_until(lambda: _get_snapshot(rss, snapshot),
                       lambda s: s is not None and s["status"] == "AVAILABLE",
                       timeout_s=900, interval_s=15, what=f"snapshot {snapshot} AVAILABLE")
    assert snap["namespaceName"] == src_ns, f"snapshot names the wrong namespace: {snap!r}"

    restored = rss.restore_from_snapshot(namespaceName=dst_ns, workgroupName=dst_wg,
                                        snapshotName=snapshot)
    assert restored["snapshotName"] == snapshot, restored
    assert restored["namespace"]["namespaceName"] == dst_ns, restored["namespace"]
    assert restored["namespace"]["namespaceId"] == dst_id, (
        f"restore replaced the target namespace identity: {restored['namespace']!r}")

    # The restore takes the target namespace and its workgroup through MODIFYING and back.
    _poll_until(lambda: _namespace_status(rss, dst_ns), lambda s: s == "AVAILABLE",
                timeout_s=900, interval_s=15, what=f"namespace {dst_ns} AVAILABLE after restore")
    _poll_until(lambda: _workgroup_status(rss, dst_wg), lambda s: s == "AVAILABLE",
                timeout_s=900, interval_s=15, what=f"workgroup {dst_wg} AVAILABLE after restore")

    # The payload assertion: the rows are readable out of the OTHER namespace.
    assert _select_rows(rd, dst_wg, table) == rows, (
        f"the restored namespace {dst_ns!r} does not carry the snapshotted rows")


def _poll_until(probe, predicate, *, timeout_s, interval_s, what):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{what} not reached within {timeout_s}s (last observed {last!r})")


def _absent_or_raise(fn, **kw):
    from botocore.exceptions import ClientError

    try:
        return fn(**kw)
    except ClientError as e:
        if e.response["Error"]["Code"] == "ResourceNotFoundException":
            return None
        raise


def _workgroup_status(rss, wg):
    r = _absent_or_raise(rss.get_workgroup, workgroupName=wg)
    return None if r is None else r["workgroup"]["status"]


def _namespace_status(rss, ns):
    r = _absent_or_raise(rss.get_namespace, namespaceName=ns)
    return None if r is None else r["namespace"]["status"]


def _get_snapshot(rss, name):
    r = _absent_or_raise(rss.get_snapshot, snapshotName=name)
    return None if r is None else r["snapshot"]


def _provision(ctx, rss, role):
    """Create a namespace and an 8-RPU workgroup, registering each teardown immediately.

    LIFO makes the workgroup delete run before its namespace delete, which is the only
    order that converges: DeleteNamespace is rejected with ConflictException for as long
    as a workgroup is attached.
    """
    ns = ctx.unique_name(f"sim2real-behav-rsns-{role}-")
    wg = ctx.unique_name(f"sim2real-behav-rswg-{role}-")
    created = rss.create_namespace(namespaceName=ns, dbName="dev",
                                   tags=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(lambda: _delete_namespace(rss, ns))
    rss.create_workgroup(workgroupName=wg, namespaceName=ns, baseCapacity=8,
                         publiclyAccessible=False,
                         tags=[{"key": "sim2real", "value": CHECK}], subnetIds=ctx.network().subnet_ids)
    ctx.on_cleanup(lambda: _delete_workgroup(rss, wg))
    return ns, wg, created["namespace"]["namespaceId"]


def _retry_delete(call, probe, what, *, timeout_s=900, interval_s=15):
    """Issue a delete until it is ACCEPTED, then wait for the resource to be gone.

    Both redshift-serverless deletes reject with ConflictException while the resource (or
    a resource attached to it) is still settling, so a single call is not a teardown.
    """
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            call()
            break
        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            if time.monotonic() >= deadline:
                raise RuntimeError(
                    f"{what}: delete never accepted ({e.response['Error']['Code']})"
                ) from e
            time.sleep(interval_s)
    while time.monotonic() < deadline:
        if probe() is None:
            return
        time.sleep(interval_s)
    raise RuntimeError(f"{what}: still present after {timeout_s}s")


def _delete_workgroup(rss, wg):
    _retry_delete(lambda: rss.delete_workgroup(workgroupName=wg),
                  lambda: _workgroup_status(rss, wg), f"workgroup {wg}")


def _delete_namespace(rss, ns):
    _retry_delete(lambda: rss.delete_namespace(namespaceName=ns),
                  lambda: _namespace_status(rss, ns), f"namespace {ns}")


def _delete_snapshot(rss, name):
    _retry_delete(lambda: rss.delete_snapshot(snapshotName=name),
                  lambda: _get_snapshot(rss, name), f"snapshot {name}")


def _execute_and_wait(rd, workgroup, sql, timeout_s=300):
    sid = rd.execute_statement(WorkgroupName=workgroup, Database="dev", Sql=sql)["Id"]
    final = _poll_until(lambda: rd.describe_statement(Id=sid),
                        lambda d: d["Status"] in ("FINISHED", "FAILED", "ABORTED"),
                        timeout_s=timeout_s, interval_s=3,
                        what=f"statement {sid} terminal")
    assert final["Status"] == "FINISHED", f"{sql!r} ended {final['Status']!r}: {final.get('Error')!r}"
    return sid


def _select_rows(rd, workgroup, table):
    sid = _execute_and_wait(rd, workgroup, f"SELECT id, name FROM {table} ORDER BY id")
    result = rd.get_statement_result(Id=sid)
    return [(r[0].get("longValue"), r[1].get("stringValue")) for r in result["Records"]]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
