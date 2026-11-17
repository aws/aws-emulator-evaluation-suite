"""list-schedule-groups-and-schedules-shared-name-prefix."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-schedule-groups-and-schedules-shared-name-prefix"
GROUP = "state-machine"
SERVICES = ["iam", "scheduler"]

_MANAGED_TAGS_KV = [{"Key": "sim2real:managed", "Value": "true"}]


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
    resp = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=assume_doc, Tags=_MANAGED_TAGS_KV
    )

    def _del_role():
        for pol in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            try:
                iam.delete_role_policy(RoleName=role_name, PolicyName=pol)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "NoSuchEntity":
                raise

    ctx.on_cleanup(_del_role)
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="scheduler-target",
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": "*"}],
        }),
    )
    arn = resp["Role"]["Arn"]
    ctx._sched_role_arn = arn
    return arn


def _create_schedule_with_role_propagation_retry(sch, kwargs, *, timeout_s=90.0, interval_s=3.0):
    """CreateSchedule validates its RoleArn is assumable by scheduler.amazonaws.com; a role
    created moments ago has not always propagated to that check. Retry only the specific
    eventual-consistency ValidationException, bounded, never a blind sleep."""
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return sch.create_schedule(**kwargs)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            message = exc.response.get("Error", {}).get("Message", "")
            if code == "ValidationException" and "assum" in message.lower():
                last_exc = exc
                time.sleep(interval_s)
                continue
            raise
    raise AssertionError(
        f"CreateSchedule did not accept the execution role within {timeout_s}s "
        f"(IAM propagation): {last_exc}"
    )


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


def _default_schedule_kwargs(ctx, name, group=None, expression="rate(5 minutes)"):
    kwargs = {
        "Name": name,
        "ScheduleExpression": expression,
        "FlexibleTimeWindow": _flexible_window("OFF"),
        "Target": _sqs_target(
            f"arn:aws:sqs:{ctx.region}:{ctx.account}:sim2real-behav-placeholder-target",
            _scheduler_role_arn(ctx),
        ),
    }
    if group:
        kwargs["GroupName"] = group
    return kwargs


def _track_schedule(ctx, name, group=None):
    sch = ctx.client("scheduler")

    def _del():
        kwargs = {"Name": name}
        if group:
            kwargs["GroupName"] = group
        try:
            sch.delete_schedule(**kwargs)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_del)


def _track_group(ctx, name):
    sch = ctx.client("scheduler")

    def _del():
        try:
            sch.delete_schedule_group(Name=name)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_del)


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _list_groups_by_prefix(ctx, name_prefix):
    sch = ctx.client("scheduler")
    groups = {}
    token = None
    while True:
        kw = {"MaxResults": 100, "NamePrefix": name_prefix}
        if token:
            kw["NextToken"] = token
        resp = sch.list_schedule_groups(**kw)
        for g in resp.get("ScheduleGroups", []):
            groups[g["Name"]] = g
        token = resp.get("NextToken")
        if not token:
            break
    return groups


def _list_schedules(ctx, group=None, name_prefix=None):
    sch = ctx.client("scheduler")
    schedules = {}
    token = None
    while True:
        kw = {"MaxResults": 100}
        if group:
            kw["GroupName"] = group
        if name_prefix:
            kw["NamePrefix"] = name_prefix
        if token:
            kw["NextToken"] = token
        resp = sch.list_schedules(**kw)
        for s in resp.get("Schedules", []):
            schedules[s["Name"]] = s
        token = resp.get("NextToken")
        if not token:
            break
    return schedules


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListScheduleGroups with a NamePrefix shared by two groups, but matching neither by exact
    name, returns exactly those two groups, both ACTIVE, never a sibling or the default
    group; ListSchedules pins each schedule's GroupName per filter (GroupName, NamePrefix, none)."""
    sch = ctx.client("scheduler")

    shared_prefix = ctx.unique_name("sim2real-behav-shpfx-")
    group_a = f"{shared_prefix}-a"
    group_b = f"{shared_prefix}-b"
    sibling_group = ctx.unique_name("sim2real-behav-sib-")

    sch.create_schedule_group(Name=group_a, Tags=_MANAGED_TAGS_KV)
    _track_group(ctx, group_a)
    sch.create_schedule_group(Name=group_b, Tags=_MANAGED_TAGS_KV)
    _track_group(ctx, group_b)
    sch.create_schedule_group(Name=sibling_group, Tags=_MANAGED_TAGS_KV)
    _track_group(ctx, sibling_group)

    groups = _poll_until(
        lambda: _list_groups_by_prefix(ctx, shared_prefix),
        lambda gs: group_a in gs and group_b in gs,
        description="both prefixed groups listed",
    )
    assert set(groups) == {group_a, group_b}, (
        f"NamePrefix={shared_prefix!r} returned {sorted(groups)}, expected exactly "
        f"[{group_a!r}, {group_b!r}]"
    )
    assert sorted(groups) == [group_a, group_b], (
        f"expected the two prefixed groups sorted by name, got {sorted(groups)}"
    )
    for name in (group_a, group_b):
        assert groups[name]["State"] == "ACTIVE", (
            f"group {name!r} in the prefix filter has State={groups[name]['State']!r}, expected ACTIVE"
        )
    assert sibling_group not in groups, (
        f"sibling group {sibling_group!r} leaked into NamePrefix={shared_prefix!r}: {sorted(groups)}"
    )
    assert "default" not in groups, (
        f"default group leaked into NamePrefix={shared_prefix!r}: {sorted(groups)}"
    )

    exact_prefix_groups = _list_groups_by_prefix(ctx, group_a)
    assert set(exact_prefix_groups) == {group_a}, (
        f"NamePrefix={group_a!r} returned {sorted(exact_prefix_groups)}, expected exactly [{group_a!r}]"
    )

    sched_prefix = ctx.unique_name("sim2real-behav-schpfx-")
    s1_default = f"{sched_prefix}-def"
    s2_grouped = f"{sched_prefix}-grp"

    _create_schedule_with_role_propagation_retry(
        sch, _default_schedule_kwargs(ctx, s1_default)
    )
    _track_schedule(ctx, s1_default)
    _create_schedule_with_role_propagation_retry(
        sch, _default_schedule_kwargs(ctx, s2_grouped, group=group_a)
    )
    _track_schedule(ctx, s2_grouped, group_a)

    all_schedules = _poll_until(
        lambda: _list_schedules(ctx),
        lambda ss: s1_default in ss and s2_grouped in ss,
        description="both schedules listed across groups",
    )
    this_check = {
        name: s for name, s in all_schedules.items() if name in (s1_default, s2_grouped)
    }
    assert this_check[s1_default]["GroupName"] == "default", (
        f"{s1_default!r} has GroupName={this_check[s1_default]['GroupName']!r} in the unfiltered "
        f"listing, expected 'default'"
    )
    assert this_check[s2_grouped]["GroupName"] == group_a, (
        f"{s2_grouped!r} has GroupName={this_check[s2_grouped]['GroupName']!r} in the unfiltered "
        f"listing, expected {group_a!r}"
    )

    group_a_schedules = _list_schedules(ctx, group=group_a)
    assert set(group_a_schedules) == {s2_grouped}, (
        f"GroupName={group_a!r} returned {sorted(group_a_schedules)}, expected exactly [{s2_grouped!r}]"
    )
    assert group_a_schedules[s2_grouped]["GroupName"] == group_a, (
        f"GroupName-filtered entry for {s2_grouped!r} reports GroupName="
        f"{group_a_schedules[s2_grouped]['GroupName']!r}, expected {group_a!r}"
    )

    prefix_schedules = _list_schedules(ctx, name_prefix=sched_prefix)
    assert set(prefix_schedules) == {s1_default, s2_grouped}, (
        f"NamePrefix={sched_prefix!r} returned {sorted(prefix_schedules)}, expected exactly "
        f"[{s1_default!r}, {s2_grouped!r}] across both groups"
    )
    assert prefix_schedules[s1_default]["GroupName"] == "default", (
        f"NamePrefix-filtered entry for {s1_default!r} reports GroupName="
        f"{prefix_schedules[s1_default]['GroupName']!r}, expected 'default'"
    )
    assert prefix_schedules[s2_grouped]["GroupName"] == group_a, (
        f"NamePrefix-filtered entry for {s2_grouped!r} reports GroupName="
        f"{prefix_schedules[s2_grouped]['GroupName']!r}, expected {group_a!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
