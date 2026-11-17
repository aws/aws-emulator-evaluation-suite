"""crawler-schedule-no-schedule-and-unknown-crawler-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "crawler-schedule-no-schedule-and-unknown-crawler-rejected"
GROUP = "state-machine"
SERVICES = ["glue", "iam"]


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _delete_role(iam, name):
    try:
        for pol in iam.list_attached_role_policies(RoleName=name).get("AttachedPolicies", []):
            iam.detach_role_policy(RoleName=name, PolicyArn=pol["PolicyArn"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_role(RoleName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _glue_role_arn(ctx, iam):
    """An IAM role Glue can assume, torn down by this check."""
    name = ctx.unique_name("sim2real-behav-glue-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "glue.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    resp = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_role(iam, name))
    iam.attach_role_policy(
        RoleName=name, PolicyArn="arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole"
    )
    return resp["Role"]["Arn"]


def _retry_iam_propagation(fn, *, timeout_s=60.0, interval_s=5.0):
    """A freshly-created role's AssumeRole probe can lag IAM propagation; retry on exactly
    that transient pair, bounded by a deadline."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in ("AccessDeniedException", "InvalidInputException") and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise


def _poll(fn, pred, timeout_s, interval_s):
    deadline = time.time() + timeout_s
    val = fn()
    while not pred(val):
        if time.time() >= deadline:
            return val
        time.sleep(interval_s)
        val = fn()
    return val


def _schedule_state(glue, crawler_name):
    return glue.get_crawler(Name=crawler_name)["Crawler"]["Schedule"]["State"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """StartCrawlerSchedule on a crawler with no cron set fails NoScheduleException, a crawler
    with a cron toggles SCHEDULED/NOT_SCHEDULED through Start/StopCrawlerSchedule, and a crawler
    name nobody created is EntityNotFoundException with the name quoted for both operations.
    """
    glue = ctx.client("glue")
    iam = ctx.client("iam")
    role = _glue_role_arn(ctx, iam)

    db_name = ctx.unique_name("sim2real-behav-db-")
    glue.create_database(DatabaseInput={"Name": db_name})
    ctx.on_cleanup(lambda: glue.delete_database(Name=db_name))

    unscheduled = ctx.unique_name("sim2real-behav-crawler-noshed-")
    _retry_iam_propagation(
        lambda: glue.create_crawler(
            Name=unscheduled,
            Role=role,
            DatabaseName=db_name,
            Targets={"S3Targets": [{"Path": "s3://example-bucket/data/"}]},
        )
    )
    ctx.on_cleanup(lambda: glue.delete_crawler(Name=unscheduled))

    # A crawler with no cron expression has nothing for StartCrawlerSchedule to start.
    code, message = _error(lambda: glue.start_crawler_schedule(CrawlerName=unscheduled))
    assert code == "NoScheduleException", f"expected NoScheduleException, got {code}: {message!r}"
    assert message == "No schedule found.", f"unexpected NoScheduleException message: {message!r}"

    scheduled = ctx.unique_name("sim2real-behav-crawler-sched-")
    glue.create_crawler(
        Name=scheduled,
        Role=role,
        DatabaseName=db_name,
        Targets={"S3Targets": [{"Path": "s3://example-bucket/data/"}]},
        Schedule="cron(0 1 * * ? *)",
    )
    ctx.on_cleanup(lambda: glue.delete_crawler(Name=scheduled))
    state = _poll(
        lambda: _schedule_state(glue, scheduled), lambda s: s == "SCHEDULED", timeout_s=60, interval_s=2
    )
    assert state == "SCHEDULED", f"crawler created with a Schedule did not reach SCHEDULED: {state!r}"

    # Positive control: pausing the schedule that really is running succeeds.
    glue.stop_crawler_schedule(CrawlerName=scheduled)
    paused = _poll(
        lambda: _schedule_state(glue, scheduled), lambda s: s == "NOT_SCHEDULED", timeout_s=60, interval_s=2
    )
    assert paused == "NOT_SCHEDULED", f"StopCrawlerSchedule did not reach NOT_SCHEDULED: {paused!r}"

    # Restore: the identical start call that follows a real pause succeeds.
    glue.start_crawler_schedule(CrawlerName=scheduled)
    resumed = _poll(
        lambda: _schedule_state(glue, scheduled), lambda s: s == "SCHEDULED", timeout_s=60, interval_s=2
    )
    assert resumed == "SCHEDULED", f"StartCrawlerSchedule did not resume to SCHEDULED: {resumed!r}"

    # A crawler name nobody created is EntityNotFoundException for both operations.
    missing = ctx.unique_name("sim2real-behav-crawler-missing-")
    expected_missing = f"Crawler with name {missing} does not exist not found."
    code, message = _error(lambda: glue.start_crawler_schedule(CrawlerName=missing))
    assert code == "EntityNotFoundException", f"expected EntityNotFoundException, got {code}: {message!r}"
    assert message == expected_missing, f"unexpected message for a missing crawler: {message!r}"
    code, message = _error(lambda: glue.stop_crawler_schedule(CrawlerName=missing))
    assert code == "EntityNotFoundException", f"expected EntityNotFoundException, got {code}: {message!r}"
    assert message == expected_missing, f"unexpected message for a missing crawler: {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
