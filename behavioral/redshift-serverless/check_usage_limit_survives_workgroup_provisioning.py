"""usage-limit-survives-workgroup-provisioning."""
from __future__ import annotations

import time

from behavioral_harness import tags


CHECK = "usage-limit-survives-workgroup-provisioning"
GROUP = "lifecycle"
SERVICES = ["redshift-serverless"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A usage limit created while its workgroup is CREATING is still listed after it is AVAILABLE,
    UpdateUsageLimit persists, and after delete GetUsageLimit answers ValidationException."""
    rss = ctx.client("redshift-serverless")

    ns = ctx.unique_name("sim2real-behav-rsns-")
    wg = ctx.unique_name("sim2real-behav-rswg-")
    rss.create_namespace(namespaceName=ns, dbName="dev",
                         tags=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(lambda: _delete_namespace(rss, ns))
    created = rss.create_workgroup(workgroupName=wg, namespaceName=ns, baseCapacity=8,
                                  publiclyAccessible=False,
                                  tags=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(lambda: _delete_workgroup(rss, wg))
    assert created["workgroup"]["status"] == "CREATING", created["workgroup"]["status"]
    wg_arn = created["workgroup"]["workgroupArn"]

    limit = rss.create_usage_limit(resourceArn=wg_arn, usageType="serverless-compute",
                                   amount=60, period="daily", breachAction="log")["usageLimit"]
    limit_id = limit["usageLimitId"]
    ctx.on_cleanup(lambda: _delete_usage_limit(rss, limit_id))
    assert limit["amount"] == 60, limit
    assert limit["period"] == "daily", limit
    assert limit["breachAction"] == "log", limit
    assert limit["resourceArn"] == wg_arn, limit

    _poll_until(lambda: _workgroup_status(rss, wg), lambda s: s == "AVAILABLE",
                timeout_s=900, interval_s=10, what=f"workgroup {wg} AVAILABLE")

    # The limit is still bound to the workgroup after provisioning finished. Scoped to OUR
    # workgroup's ARN, never an account-wide listing.
    after = rss.list_usage_limits(resourceArn=wg_arn)["usageLimits"]
    assert [u["usageLimitId"] for u in after] == [limit_id], (
        f"the usage limit did not survive provisioning: {after!r}")
    assert after[0]["amount"] == 60, after[0]

    rss.update_usage_limit(usageLimitId=limit_id, amount=120)
    reread = rss.get_usage_limit(usageLimitId=limit_id)["usageLimit"]
    assert reread["amount"] == 120, f"UpdateUsageLimit was not durable: {reread!r}"
    assert reread["period"] == "daily", reread
    assert reread["resourceArn"] == wg_arn, reread

    rss.delete_usage_limit(usageLimitId=limit_id)
    assert rss.list_usage_limits(resourceArn=wg_arn)["usageLimits"] == [], (
        "the deleted usage limit is still listed against the workgroup")
    code, message = _error(lambda: rss.get_usage_limit(usageLimitId=limit_id))
    assert code == "ValidationException", (
        f"reading a deleted usage limit returned {code!r}")
    assert message == f"The usage limit ID is not valid. {limit_id} does not exist", message


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


def _delete_usage_limit(rss, limit_id):
    """Idempotent: the check deletes this limit itself, and a deleted id reads as invalid."""
    from botocore.exceptions import ClientError

    try:
        rss.delete_usage_limit(usageLimitId=limit_id)
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code != "ValidationException":  # an id the check already deleted reads back as invalid
            raise RuntimeError(f"usage limit {limit_id}: {code}") from e


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
