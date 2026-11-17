"""crawler-schedule-lifecycle-toggles-state."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "crawler-schedule-lifecycle-toggles-state"
GROUP = "lifecycle"
SERVICES = ["glue", "iam", "s3"]


@tags("axis:happy-path", "cap:c4", "concern:representation", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A scheduled crawler starts SCHEDULED; StopCrawlerSchedule and StartCrawlerSchedule toggle it
    to NOT_SCHEDULED and back, each read independently. StartCrawlerSchedule raises
    NoScheduleException on a crawler with no schedule and EntityNotFoundException on an unknown one.
    """
    glue = ctx.client("glue")
    role_arn = _glue_role_arn(ctx)
    bucket = _probe_bucket(ctx)
    db_name = ctx.unique_name("sim2real_behav_glue_crsched_db_")
    glue.create_database(DatabaseInput={"Name": db_name})
    ctx.on_cleanup(lambda: glue.delete_database(Name=db_name))

    scheduled_name = ctx.unique_name("sim2real-behav-glue-crsched-")
    bare_name = ctx.unique_name("sim2real-behav-glue-crbare-")
    missing_name = ctx.unique_name("sim2real-behav-glue-crmissing-")

    _create_crawler(ctx, glue, role_arn, db_name, bucket, scheduled_name, "data",
                     schedule="cron(15 12 * * ? *)")
    _create_crawler(ctx, glue, role_arn, db_name, bucket, bare_name, "bare", schedule=None)

    initial = _poll_schedule_state(glue, scheduled_name, "SCHEDULED")
    assert initial["ScheduleExpression"] == "cron(15 12 * * ? *)", (
        f"expected the stored cron expression 'cron(15 12 * * ? *)', got "
        f"{initial.get('ScheduleExpression')!r}"
    )

    glue.stop_crawler_schedule(CrawlerName=scheduled_name)
    stopped = _poll_schedule_state(glue, scheduled_name, "NOT_SCHEDULED")
    assert stopped["ScheduleExpression"] == "cron(15 12 * * ? *)", (
        "StopCrawlerSchedule must not clear the stored cron expression, got "
        f"{stopped.get('ScheduleExpression')!r}"
    )

    glue.start_crawler_schedule(CrawlerName=scheduled_name)
    restarted = _poll_schedule_state(glue, scheduled_name, "SCHEDULED")
    assert restarted["ScheduleExpression"] == "cron(15 12 * * ? *)", (
        "StartCrawlerSchedule must not alter the stored cron expression, got "
        f"{restarted.get('ScheduleExpression')!r}"
    )

    code, message = _error(lambda: glue.start_crawler_schedule(CrawlerName=bare_name))
    assert code == "NoScheduleException", (
        f"expected StartCrawlerSchedule on a crawler with no Schedule to raise "
        f"NoScheduleException, got {code!r} ({message!r})"
    )
    assert message == "No schedule found.", (
        f"expected the NoScheduleException message 'No schedule found.', got {message!r}"
    )

    code, message = _error(lambda: glue.start_crawler_schedule(CrawlerName=missing_name))
    assert code == "EntityNotFoundException", (
        f"expected StartCrawlerSchedule on an unknown crawler to raise EntityNotFoundException, "
        f"got {code!r} ({message!r})"
    )
    expected_missing = f"Crawler with name {missing_name} does not exist not found."
    assert message == expected_missing, f"expected {expected_missing!r}, got {message!r}"


def _create_crawler(ctx, glue, role_arn, db_name, bucket, name, prefix, *, schedule):
    kwargs = {
        "Name": name,
        "Role": role_arn,
        "DatabaseName": db_name,
        "Targets": {"S3Targets": [{"Path": f"s3://{bucket}/{prefix}/"}]},
        "Description": "sim2real probe crawler",
    }
    if schedule is not None:
        kwargs["Schedule"] = schedule
    _retry_role_propagation(lambda: glue.create_crawler(**kwargs))
    ctx.on_cleanup(lambda: _delete_crawler(glue, name))


def _retry_role_propagation(fn, *, budget_s: float = 90.0, interval_s: float = 5.0):
    """IAM propagation exposes no condition to poll: retry the bounded AccessDenied window."""
    deadline = time.monotonic() + budget_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("InvalidInputException", "AccessDeniedException"):
                raise
            if time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _poll_schedule_state(glue, name, want_state, *, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    schedule = glue.get_crawler(Name=name)["Crawler"].get("Schedule", {})
    while schedule.get("State") != want_state:
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"crawler {name!r} schedule state never reached {want_state!r}; last seen "
                f"{schedule!r}"
            )
        time.sleep(interval_s)
        schedule = glue.get_crawler(Name=name)["Crawler"].get("Schedule", {})
    return schedule


def _delete_crawler(glue, name):
    try:
        glue.delete_crawler(Name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "EntityNotFoundException":
            raise


def _glue_role_arn(ctx):
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-glue-crsched-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "glue.amazonaws.com"},
             "Action": "sts:AssumeRole"}
        ],
    }
    resp = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Description="sim2real behavioral fidelity check role",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    return resp["Role"]["Arn"]


def _probe_bucket(ctx):
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-behav-glue-crsched-bucket-")
    kwargs = {"Bucket": name}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=name))
    return name


def _error(fn) -> tuple[str, str]:
    """Call fn(); return the AWS error (Code, Message) it raised. An unexpected SUCCESS raises,
    so a target that accepts what AWS refuses fails loudly."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
