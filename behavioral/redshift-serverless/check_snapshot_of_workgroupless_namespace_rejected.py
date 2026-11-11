"""snapshot-of-workgroupless-namespace-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags


CHECK = "snapshot-of-workgroupless-namespace-rejected"
GROUP = "lifecycle"
SERVICES = ["redshift-serverless"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateSnapshot on a namespace with no workgroup is rejected with ResourceNotFoundException and
    its exact message and lists no snapshot, then succeeds once a workgroup exists."""
    rss = ctx.client("redshift-serverless")

    ns = ctx.unique_name("sim2real-behav-rsns-")
    rss.create_namespace(namespaceName=ns, dbName="dev",
                         tags=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(lambda: _delete_namespace(rss, ns))
    _poll_until(lambda: _namespace_status(rss, ns), lambda s: s == "AVAILABLE",
                timeout_s=600, interval_s=5, what=f"namespace {ns} AVAILABLE")

    snapshot = ctx.unique_name("sim2real-behav-rssnap-")
    code, message = _error(lambda: rss.create_snapshot(namespaceName=ns, snapshotName=snapshot,
                                                       retentionPeriod=1))
    assert code == "ResourceNotFoundException", (
        f"snapshotting a workgroupless namespace returned {code!r}")
    assert message == (
        "You can't create a snapshot because there isn't a workgroup created for the namespace."
    ), message

    # The rejection left no snapshot behind. Scoped to OUR namespace, never an account-wide list.
    assert rss.list_snapshots(namespaceName=ns)["snapshots"] == [], (
        f"the rejected CreateSnapshot still created a snapshot on {ns!r}")

    # Positive control: the only thing that was missing is compute, at the 8-RPU minimum.
    wg = ctx.unique_name("sim2real-behav-rswg-")
    rss.create_workgroup(workgroupName=wg, namespaceName=ns, baseCapacity=8,
                         publiclyAccessible=False,
                         tags=[{"key": "sim2real", "value": CHECK}], subnetIds=ctx.network().subnet_ids)
    ctx.on_cleanup(lambda: _delete_workgroup(rss, wg))
    _poll_until(lambda: _workgroup_status(rss, wg), lambda s: s == "AVAILABLE",
                timeout_s=900, interval_s=10, what=f"workgroup {wg} AVAILABLE")

    created = rss.create_snapshot(namespaceName=ns, snapshotName=snapshot, retentionPeriod=1,
                                 tags=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(lambda: _delete_snapshot(rss, snapshot))
    assert created["snapshot"]["namespaceName"] == ns, created["snapshot"]
    assert [s["snapshotName"] for s in rss.list_snapshots(namespaceName=ns)["snapshots"]] == [snapshot]


def _poll_until(probe, predicate, *, timeout_s, interval_s, what):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{what} not reached within {timeout_s}s (last observed {last!r})")


def _error(fn):
    """The (code, message) of the ClientError ``fn`` raises; a call that succeeds fails the check."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
    raise AssertionError(f"expected a rejection but the call SUCCEEDED, returning {result!r}")


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


def _retry_delete(call, probe, what, *, timeout_s=900, interval_s=15):
    """Issue a delete until it is ACCEPTED, then wait for the resource to be gone.

    redshift-serverless rejects these deletes with ConflictException for as long as the
    resource -- or a resource attached to it -- is still settling, so a single call is not
    a teardown.
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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
