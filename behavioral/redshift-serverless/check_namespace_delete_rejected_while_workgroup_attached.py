"""namespace-delete-rejected-while-workgroup-attached."""
from __future__ import annotations

import time

from behavioral_harness import tags


CHECK = "namespace-delete-rejected-while-workgroup-attached"
GROUP = "lifecycle"
SERVICES = ["redshift-serverless"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteNamespace is rejected with ConflictException and its exact message while a workgroup is
    attached, leaving both AVAILABLE; once the workgroup is gone it succeeds and GetNamespace
    answers ResourceNotFoundException."""
    rss = ctx.client("redshift-serverless")

    ns = ctx.unique_name("sim2real-behav-rsns-")
    wg = ctx.unique_name("sim2real-behav-rswg-")
    rss.create_namespace(namespaceName=ns, dbName="dev",
                         tags=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(lambda: _delete_namespace(rss, ns))
    rss.create_workgroup(workgroupName=wg, namespaceName=ns, baseCapacity=8,
                         publiclyAccessible=False,
                         tags=[{"key": "sim2real", "value": CHECK}], subnetIds=ctx.network().subnet_ids)
    ctx.on_cleanup(lambda: _delete_workgroup(rss, wg))
    _poll_until(lambda: _workgroup_status(rss, wg), lambda s: s == "AVAILABLE",
                timeout_s=900, interval_s=10, what=f"workgroup {wg} AVAILABLE")

    code, message = _error(lambda: rss.delete_namespace(namespaceName=ns))
    assert code == "ConflictException", (
        f"deleting a namespace with an attached workgroup returned {code!r}")
    assert message == f"Delete the associated workgroup {wg} before you delete the namespace.", message

    # The rejected delete did not start tearing the namespace down.
    assert _namespace_status(rss, ns) == "AVAILABLE", (
        f"namespace {ns!r} left {_namespace_status(rss, ns)!r} by a rejected delete")
    assert _workgroup_status(rss, wg) == "AVAILABLE", (
        f"workgroup {wg!r} left {_workgroup_status(rss, wg)!r} by a rejected namespace delete")

    # Positive control: remove the only thing blocking it and the same call succeeds.
    _delete_workgroup(rss, wg)
    assert _workgroup_status(rss, wg) is None, f"workgroup {wg!r} outlived its delete"

    deleted = _accept_delete(lambda: rss.delete_namespace(namespaceName=ns),
                            what=f"namespace {ns} delete")
    assert deleted["namespace"]["namespaceName"] == ns, deleted["namespace"]
    _poll_until(lambda: _namespace_status(rss, ns), lambda s: s is None,
                timeout_s=900, interval_s=15, what=f"namespace {ns} gone")
    code, message = _error(lambda: rss.get_namespace(namespaceName=ns))
    assert code == "ResourceNotFoundException", (
        f"a deleted namespace is still readable, GetNamespace returned {code!r}")
    assert message == f"Serverless namespace {ns} not found.", message


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


def _accept_delete(call, *, what, timeout_s=900, interval_s=15):
    """Retry a delete until the service ACCEPTS it, and fail loudly if it never does.

    Used for the positive control, where the delete being accepted is the assertion -- not for
    teardown, which must never fail the check it is cleaning up after.
    """
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            return call()
        except ClientError as e:
            last = e.response["Error"]["Code"]
            if last != "ConflictException":
                raise
            time.sleep(interval_s)
    raise AssertionError(f"{what} was never accepted within {timeout_s}s (last {last!r})")


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


def _retry_delete(call, probe, what, *, timeout_s=900, interval_s=15):
    """Issue a delete until it is ACCEPTED, then wait for the resource to be gone."""
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
                print(f"{what}: delete never accepted ({e.response['Error']['Code']})")
                return
            time.sleep(interval_s)
    while time.monotonic() < deadline:
        if probe() is None:
            return
        time.sleep(interval_s)
    print(f"{what}: still present after {timeout_s}s")


def _delete_workgroup(rss, wg):
    _retry_delete(lambda: rss.delete_workgroup(workgroupName=wg),
                  lambda: _workgroup_status(rss, wg), f"workgroup {wg}")


def _delete_namespace(rss, ns):
    _retry_delete(lambda: rss.delete_namespace(namespaceName=ns),
                  lambda: _namespace_status(rss, ns), f"namespace {ns}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
