"""concurrent-create-schedule-same-name."""
from __future__ import annotations

import json
import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-create-schedule-same-name"
GROUP = 'concurrency'
SERVICES = ['scheduler']

_MANAGED_TAGS_KV = [{"Key": "sim2real:managed", "Value": "true"}]

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
    resp = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=assume_doc, Tags=_MANAGED_TAGS_KV,
    )

    def _del_role():
        for pol in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            try:
                iam.delete_role_policy(RoleName=role_name, PolicyName=pol)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
        iam.delete_role(RoleName=role_name)

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
    probe_target = _sqs_target(
        f"arn:aws:sqs:{ctx.region}:{_account_id(ctx)}:sim2real-behav-placeholder-target",
        arn,
    )
    _wait_for_role_ready(ctx, probe_target)
    ctx._sched_role_arn = arn
    return arn


def _wait_for_role_ready(ctx, target, max_wait_s=90, interval_s=5):
    """IAM role trust propagation lags CreateRole; probe with a throwaway schedule
    until Scheduler accepts the freshly-created execution role."""
    sch = ctx.client("scheduler")
    probe_name = ctx.unique_name("sim2real-behav-sched-warmup-")
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
            if code == "ValidationException" and "assume" in msg.lower() and time.monotonic() < deadline:
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


def _run_concurrent(fns, *, timeout_s=60):
    import concurrent.futures

    results = [None] * len(fns)
    ex = concurrent.futures.ThreadPoolExecutor(max_workers=max(1, len(fns)))
    try:
        futs = {ex.submit(fn): i for i, fn in enumerate(fns)}
        for fut in concurrent.futures.as_completed(futs, timeout=timeout_s):
            i = futs[fut]
            try:
                results[i] = fut.result()
            except Exception as exc:  # noqa: BLE001 — captured for the caller to assert on
                results[i] = exc
    except concurrent.futures.TimeoutError:
        for fut, i in futs.items():
            if not fut.done():
                results[i] = TimeoutError("run_concurrent deadline exceeded")
                fut.cancel()
    finally:
        ex.shutdown(wait=False, cancel_futures=True)
    return results


def _concurrent_successes(results):
    return sum(1 for r in results if not isinstance(r, BaseException))


def _concurrent_errors(results):
    """(code, message) for every failed attempt; a non-AWS exception reports its type name."""
    errors = []
    for r in results:
        if isinstance(r, ClientError):
            errors.append((r.response.get("Error", {}).get("Code"), r.response.get("Error", {}).get("Message")))
        elif isinstance(r, BaseException):
            errors.append((type(r).__name__, str(r)))
    return errors

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Concurrency: racing CreateSchedule calls with the same Name must yield exactly one success."""
    sch = ctx.client("scheduler")
    name = ctx.unique_name("sim2real-behav-" + "sched-")
    kwargs = _default_schedule_kwargs(ctx, name)

    def attempt():
        return sch.create_schedule(**kwargs)

    results = _run_concurrent([attempt for _ in range(6)])
    _track_schedule(ctx, name)

    n_success = _concurrent_successes(results)
    assert n_success == 1, f"expected exactly 1 success, got {n_success}"

    errors = _concurrent_errors(results)
    expected = ("ConflictException", f"Schedule {name} already exists.")
    assert all(err == expected for err in errors), f"expected every failure to be {expected!r}, got {errors}"
    assert len(errors) == 5, f"expected 5 rejections, got {len(errors)}"

    # Exactly one schedule must exist afterwards, and it must be readable.
    got = sch.get_schedule(Name=name)
    assert got["Name"] == name


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
