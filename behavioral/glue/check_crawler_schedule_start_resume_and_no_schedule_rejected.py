"""crawler-schedule-start-resume-and-no-schedule-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "crawler-schedule-start-resume-and-no-schedule-rejected"
GROUP = "crawler"
SERVICES = ["glue"]


def _error_code(fn) -> str:
    """The Error.Code ``fn`` raises. An unexpected success raises too, naming what came back."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"]
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _error(fn) -> tuple[str, str]:
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _retry_iam_propagation(fn, *, timeout_s: float = 90.0, interval_s: float = 5.0):
    """A role Glue just assumed for the first time can still 400 for a few seconds
    while the new role/policy attachment propagates."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in ("AccessDeniedException", "InvalidInputException") \
                    and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise


def _schedule_state(glue, name: str) -> str:
    return glue.get_crawler(Name=name)["Crawler"]["Schedule"]["State"]


def _poll_schedule_state(glue, name: str, want: str, *, timeout_s: float = 90.0, interval_s: float = 3.0) -> str:
    deadline = time.monotonic() + timeout_s
    state = _schedule_state(glue, name)
    while state != want:
        if time.monotonic() >= deadline:
            return state
        time.sleep(interval_s)
        state = _schedule_state(glue, name)
    return state


def _create_bucket(ctx, s3) -> str:
    bucket = ctx.unique_name("sim2real-behav-cs-").lower()
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(_teardown(lambda: s3.delete_bucket(Bucket=bucket), "NoSuchBucket"))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
    return bucket


def _glue_role_arn(ctx, iam) -> str:
    role_name = ctx.unique_name("sim2real-behav-cs-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "glue.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=role_name), "NoSuchEntity"))
    iam.attach_role_policy(
        RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole"
    )
    ctx.on_cleanup(_teardown(
        lambda: iam.detach_role_policy(
            RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole"
        ),
        "NoSuchEntity",
    ))
    return role["Role"]["Arn"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """StartCrawlerSchedule resumes a stopped schedule back to SCHEDULED and is idempotent
    while already running; it rejects a crawler that has never had a schedule at all.
    """
    glue = ctx.client("glue")
    iam = ctx.client("iam")
    s3 = ctx.client("s3")
    role_arn = _glue_role_arn(ctx, iam)
    bucket = _create_bucket(ctx, s3)

    db_name = ctx.unique_name("sim2real_behav_cs_db_").replace("-", "_")
    glue.create_database(DatabaseInput={"Name": db_name}, Tags={"sim2real": CHECK})
    ctx.on_cleanup(_teardown(lambda: glue.delete_database(Name=db_name), "EntityNotFoundException"))

    schedule_expr = "cron(0 3 * * ? *)"
    scheduled_name = ctx.unique_name("sim2real-behav-cs-scheduled-")
    _retry_iam_propagation(lambda: glue.create_crawler(
        Name=scheduled_name,
        Role=role_arn,
        DatabaseName=db_name,
        Targets={"S3Targets": [{"Path": f"s3://{bucket}/data/"}]},
        Schedule=schedule_expr,
    ))
    ctx.on_cleanup(_teardown(lambda: glue.delete_crawler(Name=scheduled_name), "EntityNotFoundException"))

    unscheduled_name = ctx.unique_name("sim2real-behav-cs-unscheduled-")
    _retry_iam_propagation(lambda: glue.create_crawler(
        Name=unscheduled_name,
        Role=role_arn,
        DatabaseName=db_name,
        Targets={"S3Targets": [{"Path": f"s3://{bucket}/other/"}]},
    ))
    ctx.on_cleanup(_teardown(lambda: glue.delete_crawler(Name=unscheduled_name), "EntityNotFoundException"))

    # negative: a crawler that has never had a schedule cannot have its schedule started
    code, msg = _error(lambda: glue.start_crawler_schedule(CrawlerName=unscheduled_name))
    assert code == "NoScheduleException", f"starting a schedule-less crawler gave {code!r}, not NoScheduleException"
    assert msg == "No schedule found.", f"unexpected NoScheduleException message: {msg!r}"
    crawler_after_rejected_start = glue.get_crawler(Name=unscheduled_name)["Crawler"]
    assert "Schedule" not in crawler_after_rejected_start, (
        f"a rejected StartCrawlerSchedule must not create a schedule, got "
        f"{crawler_after_rejected_start.get('Schedule')!r}"
    )

    # the scheduled crawler starts SCHEDULED by virtue of having a Schedule at creation
    created_state = _poll_schedule_state(glue, scheduled_name, "SCHEDULED")
    assert created_state == "SCHEDULED", f"crawler created with a Schedule was {created_state!r}, not SCHEDULED"

    glue.stop_crawler_schedule(CrawlerName=scheduled_name)
    stopped_state = _poll_schedule_state(glue, scheduled_name, "NOT_SCHEDULED")
    assert stopped_state == "NOT_SCHEDULED", f"StopCrawlerSchedule left state {stopped_state!r}"

    # positive control: StartCrawlerSchedule resumes a stopped schedule
    glue.start_crawler_schedule(CrawlerName=scheduled_name)
    resumed_state = _poll_schedule_state(glue, scheduled_name, "SCHEDULED")
    assert resumed_state == "SCHEDULED", f"StartCrawlerSchedule did not resume to SCHEDULED, got {resumed_state!r}"

    # starting a schedule that is already running is idempotent, not rejected
    glue.start_crawler_schedule(CrawlerName=scheduled_name)
    still_scheduled = _schedule_state(glue, scheduled_name)
    assert still_scheduled == "SCHEDULED", (
        f"a repeated StartCrawlerSchedule on an already-running schedule changed state to "
        f"{still_scheduled!r}"
    )

    # stopping a running schedule succeeds, and a repeat stop is idempotent too
    glue.stop_crawler_schedule(CrawlerName=scheduled_name)
    stopped_again = _poll_schedule_state(glue, scheduled_name, "NOT_SCHEDULED")
    assert stopped_again == "NOT_SCHEDULED", f"second StopCrawlerSchedule left state {stopped_again!r}"
    glue.stop_crawler_schedule(CrawlerName=scheduled_name)
    still_stopped = _schedule_state(glue, scheduled_name)
    assert still_stopped == "NOT_SCHEDULED", (
        f"a repeated StopCrawlerSchedule on an already-stopped schedule changed state to {still_stopped!r}"
    )

    # restore: StartCrawlerSchedule still resumes the schedule after the repeat stop
    glue.start_crawler_schedule(CrawlerName=scheduled_name)
    restored_state = _poll_schedule_state(glue, scheduled_name, "SCHEDULED")
    assert restored_state == "SCHEDULED", f"restoring StartCrawlerSchedule left state {restored_state!r}"

    # delete proves gone: a crawler that no longer exists cannot be read back
    glue.delete_crawler(Name=scheduled_name)
    code3 = _error_code(lambda: glue.get_crawler(Name=scheduled_name))
    assert code3 == "EntityNotFoundException", f"reading a deleted crawler gave {code3!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
