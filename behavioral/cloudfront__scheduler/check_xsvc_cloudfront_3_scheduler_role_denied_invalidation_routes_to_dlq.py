"""xsvc-cloudfront-3-scheduler-role-denied-invalidation-routes-to-dlq."""
from __future__ import annotations

import datetime as _dt
import json
import time

from behavioral_harness import tags

CHECK = "xsvc-cloudfront-3-scheduler-role-denied-invalidation-routes-to-dlq"
GROUP = "eventing"
SERVICES = ["cloudfront", "scheduler"]

#: EventBridge Scheduler's universal (aws-sdk) target for CloudFront CreateInvalidation.
_TARGET_ARN = "arn:aws:scheduler:::aws-sdk:cloudfront:createInvalidation"
_TAG_SET = [{"Key": "sim2real", "Value": "behavioral"}]
#: The DLQ message's ERROR_CODE attribute for a role without cloudfront:CreateInvalidation.
_DENIED_CODE = "AccessDenied"


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll_until(probe, predicate, *, timeout_s, interval_s=2.0, description="condition", ctx=None):
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
    return cf.create_distribution_with_tags(DistributionConfigWithTags={
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
                "CachePolicyId": "4135ea2d-6df8-44a3-9df3-4b5a84be39ad",
            },
        },
        "Tags": {"Items": _TAG_SET},
    })["Distribution"]


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


def _invalidation_paths(cf, dist_id) -> list[list[str]]:
    """Every invalidation on the distribution, as its sorted Paths, paginated."""
    out: list[list[str]] = []
    marker = None
    while True:
        kw = {"DistributionId": dist_id, "MaxItems": "100"}
        if marker:
            kw["Marker"] = marker
        page = cf.list_invalidations(**kw)["InvalidationList"]
        for item in page.get("Items", []):
            inv = cf.get_invalidation(DistributionId=dist_id, Id=item["Id"])["Invalidation"]
            out.append(sorted(inv["InvalidationBatch"]["Paths"].get("Items", [])))
        if not page.get("IsTruncated"):
            return sorted(out)
        marker = page["NextMarker"]


# timing:real-time — schedule: 20 s https://docs.aws.amazon.com/scheduler/latest/UserGuide/schedule-types.html
@tags(
    "axis:rejection",
    "concern:eventing",
    "concern:negative-classes",
    "concern:e2e",
    "cap:c1",
    "plane:control",
    "timing:real-time",
)
def run(ctx) -> None:
    """A schedule whose role lacks cloudfront:CreateInvalidation invalidates nothing and
    dead-letters with ERROR_CODE AccessDenied, while a same-instant permitted schedule invalidates;
    granting the missing permission then lets the denied role invalidate too."""
    cf = ctx.client("cloudfront")
    iam = ctx.client("iam")
    sch = ctx.client("scheduler")
    sqs = ctx.client("sqs")

    dist = _create_disabled_distribution(ctx, cf)
    dist_id = dist["Id"]
    ctx.on_cleanup(lambda: _delete_distribution_when_deployed(ctx.client("cloudfront"), dist_id))

    dlq_url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-xsvc-cfsch-dlq-"),
                               tags={"sim2real": "behavioral"})["QueueUrl"]
    ctx.on_cleanup(lambda: ctx.client("sqs").delete_queue(QueueUrl=dlq_url))
    dlq_arn = sqs.get_queue_attributes(QueueUrl=dlq_url,
                                       AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]

    send = {"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": dlq_arn}
    invalidate = {"Effect": "Allow", "Action": "cloudfront:CreateInvalidation",
                  "Resource": dist["ARN"]}
    good_role = _scheduler_role(ctx, iam, ctx.unique_name("sim2real-xsvc-cfsch-ok-"),
                                [invalidate, send])
    bad_role_name = ctx.unique_name("sim2real-xsvc-cfsch-no-")
    bad_role = _scheduler_role(ctx, iam, bad_role_name, [send])

    group = ctx.unique_name("sim2real-xsvc-cfsch-g-")
    sch.create_schedule_group(Name=group, Tags=[{"Key": "sim2real", "Value": "behavioral"}])
    ctx.on_cleanup(lambda: ctx.client("scheduler").delete_schedule_group(Name=group))

    token = ctx.unique_name("p")
    good_paths = [f"/{token}/good/*"]
    bad_paths = [f"/{token}/bad/*"]
    repaired_paths = [f"/{token}/repaired/*"]

    def schedule(role_arn, paths, seconds_ahead) -> tuple[str, str]:
        name = ctx.unique_name("sim2real-xsvc-cfsch-")
        payload = {"DistributionId": dist_id,
                   "InvalidationBatch": {"CallerReference": ctx.unique_name("ref-"),
                                         "Paths": {"Quantity": len(paths), "Items": paths}}}
        # A fresh role's trust policy reaches Scheduler after IAM propagation; until then
        # CreateSchedule refuses the role, so retry exactly that refusal until a capped deadline.
        deadline = time.monotonic() + _budget_s(ctx, 120.0)
        while True:
            try:
                arn = sch.create_schedule(
                    Name=name, GroupName=group,
                    ScheduleExpression=_at_expression(seconds_ahead), ScheduleExpressionTimezone="UTC",
                    FlexibleTimeWindow={"Mode": "OFF"},
                    Target={"Arn": _TARGET_ARN, "RoleArn": role_arn, "Input": json.dumps(payload),
                            "DeadLetterConfig": {"Arn": dlq_arn},
                            "RetryPolicy": {"MaximumRetryAttempts": 0,
                                            "MaximumEventAgeInSeconds": 60}},
                )["ScheduleArn"]
                break
            except sch.exceptions.ValidationException as exc:
                if "must allow AWS EventBridge Scheduler to assume the role" not in str(exc) \
                        or time.monotonic() >= deadline:
                    if "must allow AWS EventBridge Scheduler to assume the role" in str(exc) \
                            and _budget_spent(ctx):
                        raise TimeoutError("Scheduler to accept the new role: the run budget ended "
                                           "first; not graded") from exc
                    raise
                time.sleep(2)
        ctx.on_cleanup(lambda: ctx.client("scheduler").delete_schedule(Name=name, GroupName=group))
        return name, arn

    dead: list[dict] = []

    def drain_dlq() -> list[dict]:
        resp = sqs.receive_message(QueueUrl=dlq_url, MaxNumberOfMessages=10, WaitTimeSeconds=1,
                                   MessageAttributeNames=["All"])
        for m in resp.get("Messages", []):
            attrs = {k: v.get("StringValue") for k, v in m.get("MessageAttributes", {}).items()}
            dead.append({"attrs": attrs, "body": m["Body"]})
            sqs.delete_message(QueueUrl=dlq_url, ReceiptHandle=m["ReceiptHandle"])
        return dead

    # The bad paths' absence is asserted only after both schedules' outcomes arrived.
    _, good_arn = schedule(good_role, good_paths, 20)
    _, bad_arn = schedule(bad_role, bad_paths, 20)

    _poll_until(lambda: _invalidation_paths(cf, dist_id), lambda v: good_paths in v,
                timeout_s=_budget_s(ctx, 420.0), interval_s=1.0, ctx=ctx,
                description=f"the permitted schedule to invalidate {good_paths!r} on {dist_id}")
    _poll_until(drain_dlq, lambda d: any(x["attrs"].get("SCHEDULE_ARN") == bad_arn for x in d),
                timeout_s=_budget_s(ctx, 300.0), interval_s=1.0, ctx=ctx,
                description=f"the denied schedule's failure to reach DLQ {dlq_arn}")

    bad_dead = [x for x in dead if x["attrs"].get("SCHEDULE_ARN") == bad_arn]
    assert len(bad_dead) == 1, (
        f"one denied invocation with MaximumRetryAttempts=0 must dead-letter exactly once, got "
        f"{bad_dead!r}"
    )
    attrs = bad_dead[0]["attrs"]
    assert attrs.get("ERROR_CODE") == _DENIED_CODE, (
        f"the DLQ record must name the authorization failure: expected ERROR_CODE "
        f"{_DENIED_CODE!r}, got attributes {attrs!r}"
    )
    assert attrs.get("TARGET_ARN") == _TARGET_ARN, (
        f"the DLQ record must name the universal target it failed to invoke, got {attrs!r}"
    )
    body = json.loads(bad_dead[0]["body"])
    assert body["InvalidationBatch"]["Paths"]["Items"] == bad_paths, (
        f"the DLQ body must be the schedule's own Input, got {bad_dead[0]['body']!r}"
    )
    assert not any(x["attrs"].get("SCHEDULE_ARN") == good_arn for x in dead), (
        f"the permitted schedule must not dead-letter, got {dead!r}"
    )
    after = _invalidation_paths(cf, dist_id)
    assert after == [good_paths], (
        f"only the permitted schedule may invalidate: expected exactly [{good_paths!r}], got "
        f"{after!r}"
    )

    # Repair the one broken thing and fire again with the SAME role: it must now invalidate.
    iam.put_role_policy(RoleName=bad_role_name, PolicyName="sim2real-inline",
                        PolicyDocument=json.dumps({"Version": "2012-10-17",
                                                   "Statement": [invalidate, send]}))
    repaired_arns = []
    for attempt in range(3):  # bounded retry on AccessDenied at first use of the new grant
        _, rarn = schedule(bad_role, repaired_paths, 15)
        repaired_arns.append(rarn)

        def settled(_v, rarn=rarn):
            return repaired_paths in _invalidation_paths(cf, dist_id) or any(
                x["attrs"].get("SCHEDULE_ARN") == rarn for x in dead)

        _poll_until(drain_dlq, lambda d: settled(d), timeout_s=_budget_s(ctx, 420.0),
                    interval_s=1.0, ctx=ctx, description="the repaired schedule to invalidate or dead-letter")
        if repaired_paths in _invalidation_paths(cf, dist_id):
            break
    final = _invalidation_paths(cf, dist_id)
    assert repaired_paths in final, (
        f"after granting cloudfront:CreateInvalidation the same role must invalidate "
        f"{repaired_paths!r}; invalidations={final!r} dlq={dead!r}"
    )
    assert bad_paths not in final, (
        f"the denied schedule's paths must never be invalidated, got {final!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
