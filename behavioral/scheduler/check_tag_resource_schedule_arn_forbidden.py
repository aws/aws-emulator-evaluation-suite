"""tag-resource-schedule-arn-forbidden."""
from __future__ import annotations

import json
import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-resource-schedule-arn-forbidden"
GROUP = 'overly-permissive'
SERVICES = ['scheduler']

_THROTTLE_CODES = ("ThrottlingException", "TooManyRequestsException", "RequestThrottled")
_GROUP_ARN_PATTERN = r"arn:aws[a-z-]*:scheduler:[a-z0-9\-]+:\d{12}:schedule-group\/[0-9a-zA-Z-_.]+"


def _resource_arn_pattern_message(arn):
    return (
        f"1 validation error detected: Value '{arn}' at 'resourceArn' failed to satisfy "
        f"constraint: Member must satisfy regular expression pattern: {_GROUP_ARN_PATTERN}"
    )


def _account_id(ctx):
    cached = getattr(ctx, "_sched_account_id", None)
    if cached is None:
        try:
            cached = ctx.client("sts").get_caller_identity()["Account"]
        except Exception:
            cached = ctx.account
        ctx._sched_account_id = cached
    return cached


def _scheduler_role_arn(ctx):
    cached = getattr(ctx, "_sched_role_arn", None)
    if cached is not None:
        return cached
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-sched-role-")
    assume_doc = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "scheduler.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    })
    resp = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=assume_doc)

    def _del_role():
        for pol in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            try:
                iam.delete_role_policy(RoleName=role_name, PolicyName=pol)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_del_role)
    try:
        iam.put_role_policy(
            RoleName=role_name,
            PolicyName="scheduler-target",
            PolicyDocument=json.dumps({
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": "*"}],
            }),
        )
    except Exception:
        pass
    arn = resp["Role"]["Arn"]
    _wait_for_role_ready(ctx, arn)
    ctx._sched_role_arn = arn
    return arn


def _wait_for_role_ready(ctx, role_arn, max_wait_s=90, interval_s=5):
    """Probe with a throwaway schedule until Scheduler accepts the freshly-created execution
    role (IAM trust-policy propagation can lag CreateRole by tens of seconds)."""
    sch = ctx.client("scheduler")
    probe_name = ctx.unique_name("sim2real-behav-sched-warmup-")
    target = _sqs_target(
        f"arn:aws:sqs:{ctx.region}:{_account_id(ctx)}:sim2real-behav-placeholder-target",
        role_arn,
    )
    deadline = time.monotonic() + max_wait_s
    while True:
        try:
            sch.create_schedule(
                Name=probe_name,
                ScheduleExpression="rate(1 hour)",
                FlexibleTimeWindow=_flexible_window("OFF"),
                State="DISABLED",
                Target=target,
            )
            sch.delete_schedule(Name=probe_name)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            msg = exc.response.get("Error", {}).get("Message", "")
            if code == "ValidationException" and "assume the role" in msg and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise


def _flexible_window(mode="OFF", max_minutes=None):
    window = {"Mode": mode}
    if max_minutes is not None:
        window["MaximumWindowInMinutes"] = max_minutes
    return window


def _sqs_target(queue_arn, role_arn, input_payload=None):
    target = {"Arn": queue_arn, "RoleArn": role_arn}
    if input_payload is not None:
        target["Input"] = json.dumps(input_payload)
    return target


def _default_schedule_kwargs(ctx, name, group=None, expression="rate(5 minutes)", target=None, state=None, flexible_window=None, **extra):
    kwargs = {
        "Name": name,
        "ScheduleExpression": expression,
        "FlexibleTimeWindow": flexible_window or _flexible_window("OFF"),
        "Target": target or _sqs_target(
            f"arn:aws:sqs:{ctx.region}:{_account_id(ctx)}:sim2real-behav-placeholder-target",
            _scheduler_role_arn(ctx),
        ),
    }
    if group:
        kwargs["GroupName"] = group
    if state:
        kwargs["State"] = state
    kwargs.update(extra)
    return kwargs


def _track_schedule(ctx, name, group=None):
    sch = ctx.client("scheduler")

    def _del():
        kwargs = {"Name": name}
        if group:
            kwargs["GroupName"] = group
        sch.delete_schedule(**kwargs)

    ctx.on_cleanup(_del)


def _error(fn):
    """The botocore Error dict (Code, Message) a call raised. An unexpected SUCCESS raises, so a
    target that accepts what AWS refuses never reads as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _error_retry(fn, *, attempts=10, base_delay=1.5):
    err = {}
    for i in range(attempts):
        err = _error(fn)
        if err.get("Code") not in _THROTTLE_CODES:
            return err
        time.sleep(base_delay * (i + 1))
    return err


def _tag_map(sch, arn):
    resp = sch.list_tags_for_resource(ResourceArn=arn)
    return {t["Key"]: t["Value"] for t in resp.get("Tags", [])}

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """TagResource/ListTagsForResource accept schedule-group ARNs but reject an individual
    schedule's ARN, and the rejected calls leak no tag onto the group."""
    sch = ctx.client("scheduler")

    group_name = ctx.unique_name("sim2real-behav-sched-grp-")
    group_resp = sch.create_schedule_group(Name=group_name)
    ctx.on_cleanup(lambda: sch.delete_schedule_group(Name=group_name))
    group_arn = group_resp["ScheduleGroupArn"]

    # Positive control: the rejection below must be due to the ARN shape, not all tagging failing.
    sch.tag_resource(ResourceArn=group_arn, Tags=[{"Key": "env", "Value": "control"}])
    control_tags = _tag_map(sch, group_arn)
    assert control_tags.get("env") == "control", (
        f"positive control failed: tagging the schedule-group ARN did not reflect via "
        f"ListTagsForResource, got {control_tags!r}"
    )

    name = ctx.unique_name("sim2real-behav-" + "sched-")
    resp = sch.create_schedule(**_default_schedule_kwargs(ctx, name, group=group_name))
    _track_schedule(ctx, name, group=group_name)
    schedule_arn = resp["ScheduleArn"]
    assert ":schedule/" in schedule_arn, f"unexpected schedule ARN shape: {schedule_arn}"

    err = _error_retry(
        lambda: sch.tag_resource(
            ResourceArn=schedule_arn, Tags=[{"Key": "env", "Value": "test"}]
        )
    )
    assert err.get("Code") == "ValidationException", f"expected ValidationException, got {err.get('Code')}"
    expected_tag_message = _resource_arn_pattern_message(schedule_arn)
    assert err.get("Message") == expected_tag_message, (
        f"expected TagResource message {expected_tag_message!r}, got {err.get('Message')!r}"
    )

    # ListTagsForResource must reject the same ARN shape too.
    list_err = _error_retry(
        lambda: sch.list_tags_for_resource(ResourceArn=schedule_arn)
    )
    assert list_err.get("Code") == "ValidationException", (
        f"expected ValidationException from ListTagsForResource, got {list_err.get('Code')}"
    )
    expected_list_message = _resource_arn_pattern_message(schedule_arn)
    assert list_err.get("Message") == expected_list_message, (
        f"expected ListTagsForResource message {expected_list_message!r}, got {list_err.get('Message')!r}"
    )

    # The rejected schedule-ARN calls must not have leaked a tag onto the group.
    after_tags = _tag_map(sch, group_arn)
    assert after_tags == control_tags, (
        f"the rejected schedule-ARN tagging changed the group's tags: {after_tags!r} "
        f"!= {control_tags!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
