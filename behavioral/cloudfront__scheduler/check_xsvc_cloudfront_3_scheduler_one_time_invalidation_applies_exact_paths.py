"""xsvc-cloudfront-3-scheduler-one-time-invalidation-applies-exact-paths."""
from __future__ import annotations

import datetime as _dt
import json
import time

from behavioral_harness import tags

CHECK = "xsvc-cloudfront-3-scheduler-one-time-invalidation-applies-exact-paths"
GROUP = "eventing"
SERVICES = ["cloudfront", "scheduler"]

#: EventBridge Scheduler's universal (aws-sdk) target for CloudFront CreateInvalidation.
_TARGET_ARN = "arn:aws:scheduler:::aws-sdk:cloudfront:createInvalidation"
_TAG_SET = [{"Key": "sim2real", "Value": "behavioral"}]


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll_until(probe, predicate, *, timeout_s, interval_s=2.0, description="condition",
                ctx=None):
    """Bounded retry that RAISES on timeout - never returns its last value."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError(f"{description}: the run budget ended first; not graded")
    raise AssertionError(f"timed out waiting for {description} after {timeout_s}s (last: {last!r})")


def _create_disabled_distribution(ctx, cf) -> dict:
    """A DISABLED distribution: CreateInvalidation needs a real distribution id, not a served one,
    and a disabled distribution can be deleted as soon as it is Deployed (no disable round trip)."""
    dist = cf.create_distribution_with_tags(DistributionConfigWithTags={
        "DistributionConfig": {
            "CallerReference": ctx.unique_name("sim2real-xsvc-cfsch-cr-"),
            "Comment": "sim2real scheduler invalidation target",
            "Enabled": False,
            "Origins": {"Quantity": 1, "Items": [{
                "Id": "origin",
                "DomainName": "example.com",
                "CustomOriginConfig": {"HTTPPort": 80, "HTTPSPort": 443,
                                       "OriginProtocolPolicy": "https-only"},
            }]},
            "DefaultCacheBehavior": {
                "TargetOriginId": "origin",
                "ViewerProtocolPolicy": "allow-all",
                # Managed CachingDisabled
                "CachePolicyId": "4135ea2d-6df8-44a3-9df3-4b5a84be39ad",
            },
        },
        "Tags": {"Items": _TAG_SET},
    })["Distribution"]
    return dist


def _delete_distribution_when_deployed(cf, dist_id) -> None:
    deadline = time.monotonic() + 1200
    while time.monotonic() < deadline:
        r = cf.get_distribution(Id=dist_id)
        if r["Distribution"]["Status"] == "Deployed":
            cf.delete_distribution(Id=dist_id, IfMatch=r["ETag"])
            return
        time.sleep(3)
    raise RuntimeError(
        f"cloudfront distribution {dist_id} never reached Deployed; not deleted"
    )


def _delete_role(iam, role_name, policy_name) -> None:
    try:
        iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
    except iam.exceptions.NoSuchEntityException:
        pass
    iam.delete_role(RoleName=role_name)


def _scheduler_role(ctx, iam, name, statements) -> str:
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow",
                           "Principal": {"Service": "scheduler.amazonaws.com"},
                           "Action": "sts:AssumeRole"}],
        }),
        Description="sim2real scheduler universal-target role",
        Tags=_TAG_SET,
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(ctx.client("iam"), name, "sim2real-inline"))
    iam.put_role_policy(RoleName=name, PolicyName="sim2real-inline", PolicyDocument=json.dumps({
        "Version": "2012-10-17", "Statement": statements}))
    return arn


def _at_expression(seconds_ahead: int) -> str:
    when = _dt.datetime.now(_dt.timezone.utc) + _dt.timedelta(seconds=seconds_ahead)
    return f"at({when.strftime('%Y-%m-%dT%H:%M:%S')})"


def _list_invalidation_ids(cf, dist_id) -> list[str]:
    ids: list[str] = []
    marker = None
    while True:
        kw = {"DistributionId": dist_id, "MaxItems": "100"}
        if marker:
            kw["Marker"] = marker
        page = cf.list_invalidations(**kw)["InvalidationList"]
        ids.extend(i["Id"] for i in page.get("Items", []))
        if not page.get("IsTruncated"):
            return ids
        marker = page["NextMarker"]


# timing:real-time — schedule: 20 s https://docs.aws.amazon.com/scheduler/latest/UserGuide/schedule-types.html
@tags("axis:happy-path", "concern:eventing", "concern:e2e", "cap:c1", "plane:control", "timing:real-time")
def run(ctx) -> None:
    """A one-time EventBridge Scheduler schedule invokes CloudFront CreateInvalidation with its exact
    payload, the resulting invalidation carries exactly those Paths, and the schedule then deletes
    itself (ActionAfterCompletion=DELETE).
    """
    cf = ctx.client("cloudfront")
    iam = ctx.client("iam")
    sch = ctx.client("scheduler")

    dist = _create_disabled_distribution(ctx, cf)
    dist_id = dist["Id"]
    ctx.on_cleanup(lambda: _delete_distribution_when_deployed(ctx.client("cloudfront"), dist_id))

    role_arn = _scheduler_role(ctx, iam, ctx.unique_name("sim2real-xsvc-cfsch-ok-"), [{
        "Effect": "Allow", "Action": "cloudfront:CreateInvalidation", "Resource": dist["ARN"]}])

    group = ctx.unique_name("sim2real-xsvc-cfsch-g-")
    sch.create_schedule_group(Name=group, Tags=[{"Key": "sim2real", "Value": "behavioral"}])
    ctx.on_cleanup(lambda: ctx.client("scheduler").delete_schedule_group(Name=group))

    token = ctx.unique_name("p")
    paths = sorted([f"/{token}/index.html", f"/{token}/assets/*"])
    caller_ref = ctx.unique_name("sim2real-sched-ref-")
    payload = {"DistributionId": dist_id,
               "InvalidationBatch": {"CallerReference": caller_ref,
                                     "Paths": {"Quantity": len(paths), "Items": paths}}}

    assert _list_invalidation_ids(cf, dist_id) == [], (
        "a distribution this run just created must start with no invalidations, got "
        f"{_list_invalidation_ids(cf, dist_id)!r}"
    )

    # A fresh role's trust policy reaches Scheduler after IAM propagation; until then CreateSchedule
    # refuses the role, so retry exactly that refusal until a capped deadline, re-anchoring the at()
    # time on each attempt. The target's RetryPolicy covers a first invocation that still races the
    # role's permission policy.
    name = ctx.unique_name("sim2real-xsvc-cfsch-")
    deadline = time.monotonic() + _budget_s(ctx, 120.0)
    while True:
        try:
            sched_arn = sch.create_schedule(
                Name=name, GroupName=group,
                ScheduleExpression=_at_expression(20), ScheduleExpressionTimezone="UTC",
                FlexibleTimeWindow={"Mode": "OFF"},
                ActionAfterCompletion="DELETE",
                Target={"Arn": _TARGET_ARN, "RoleArn": role_arn, "Input": json.dumps(payload),
                        "RetryPolicy": {"MaximumRetryAttempts": 3, "MaximumEventAgeInSeconds": 300}},
            )["ScheduleArn"]
            break
        except sch.exceptions.ValidationException as exc:
            if "must allow AWS EventBridge Scheduler to assume the role" not in str(exc) \
                    or time.monotonic() >= deadline:
                if "must allow AWS EventBridge Scheduler to assume the role" in str(exc) \
                        and _budget_spent(ctx):
                    raise TimeoutError(f"CreateSchedule accepting role {role_arn}: the run budget "
                                       "ended first; not graded") from exc
                raise
            time.sleep(2)
    ctx.on_cleanup(lambda: _delete_schedule_unless_gone(ctx, name, group))
    got = sch.get_schedule(Name=name, GroupName=group)
    assert got["Arn"] == sched_arn and got["Target"]["Arn"] == _TARGET_ARN, (
        f"GetSchedule must echo the schedule and its universal target, got arn={got['Arn']!r} "
        f"target={got['Target']['Arn']!r}"
    )

    ids = _poll_until(lambda: _list_invalidation_ids(cf, dist_id), lambda v: len(v) >= 1,
                      timeout_s=_budget_s(ctx, 420.0), interval_s=1.0,
                      description=f"the schedule {name} to create an invalidation on {dist_id}",
                      ctx=ctx)
    assert len(ids) == 1, (
        f"one one-time schedule firing must create exactly one invalidation, got {ids!r}"
    )
    inv = cf.get_invalidation(DistributionId=dist_id, Id=ids[0])["Invalidation"]
    batch = inv["InvalidationBatch"]
    assert sorted(batch["Paths"].get("Items", [])) == paths, (
        f"the invalidation must carry exactly the Paths the schedule's Input requested: expected "
        f"{paths!r}, got {batch['Paths']!r}"
    )
    assert batch["Paths"]["Quantity"] == len(paths), (
        f"Paths.Quantity must be {len(paths)}, got {batch['Paths']['Quantity']!r}"
    )
    assert batch["CallerReference"] == caller_ref, (
        f"the scheduler must pass the CallerReference through unchanged: expected {caller_ref!r}, "
        f"got {batch['CallerReference']!r}"
    )
    assert inv["Status"] in ("InProgress", "Completed"), (
        f"a freshly created invalidation is InProgress or Completed, got {inv['Status']!r}"
    )

    def _schedule_gone() -> bool:
        try:
            sch.get_schedule(Name=name, GroupName=group)
            return False
        except sch.exceptions.ResourceNotFoundException:
            return True

    _poll_until(_schedule_gone, lambda gone: gone, timeout_s=_budget_s(ctx, 300.0), interval_s=1.0,
                description=f"one-time schedule {name} with ActionAfterCompletion=DELETE to be "
                            f"deleted after it fired", ctx=ctx)



def _delete_schedule_unless_gone(ctx, name, group):
    """A fired one-time schedule may already be deleted by ActionAfterCompletion; only that is tolerated."""
    sch = ctx.client("scheduler")
    try:
        sch.delete_schedule(Name=name, GroupName=group)
    except sch.exceptions.ResourceNotFoundException:
        pass


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
