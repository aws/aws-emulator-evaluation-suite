"""usage-limit-on-absent-workgroup-arn-rejected."""
from __future__ import annotations

import time
import uuid

from behavioral_harness import tags


CHECK = "usage-limit-on-absent-workgroup-arn-rejected"
GROUP = "lifecycle"
SERVICES = ["redshift-serverless"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateUsageLimit rejects a well-formed workgroup ARN naming no workgroup (this run's ARN with a
    fresh UUID) with ValidationException and its exact message, creating nothing, and accepts the
    real ARN."""
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
    real_arn = created["workgroup"]["workgroupArn"]

    absent_id = str(uuid.uuid4())
    absent_arn = real_arn.rsplit("/", 1)[0] + "/" + absent_id
    assert absent_arn != real_arn and absent_arn.startswith("arn:"), absent_arn

    code, message = _error(lambda: rss.create_usage_limit(resourceArn=absent_arn,
                                                         usageType="serverless-compute",
                                                         amount=60, period="daily"))
    assert code == "ValidationException", (
        f"a usage limit on an absent workgroup ARN returned {code!r}")
    assert message == f"The Resource ARN is not valid as the workgroup ID {absent_id}.", message

    # The rejection created nothing against the real workgroup either.
    assert rss.list_usage_limits(resourceArn=real_arn)["usageLimits"] == [], (
        "the rejected CreateUsageLimit attached a limit to the real workgroup")

    # Positive control: the same request against the ARN that does resolve.
    limit = rss.create_usage_limit(resourceArn=real_arn, usageType="serverless-compute",
                                  amount=60, period="daily")["usageLimit"]
    ctx.on_cleanup(lambda: _delete_usage_limit(rss, limit["usageLimitId"]))
    assert limit["resourceArn"] == real_arn, limit
    assert [u["usageLimitId"] for u in rss.list_usage_limits(resourceArn=real_arn)["usageLimits"]] \
        == [limit["usageLimitId"]]


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
    """Issue a delete until it is ACCEPTED, then wait for the resource to be gone.

    redshift-serverless rejects these deletes with ConflictException for as long as the resource
    -- or a resource attached to it -- is still settling, so a single call is not a teardown.
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


def _delete_usage_limit(rss, limit_id):
    from botocore.exceptions import ClientError

    try:
        rss.delete_usage_limit(usageLimitId=limit_id)
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code != "ValidationException":  # an id that no longer exists reads back as invalid
            raise RuntimeError(f"usage limit {limit_id}: {code}") from e


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
