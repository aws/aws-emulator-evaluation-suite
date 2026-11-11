"""schedule-rejects-non-cron-expression-and-unknown-job."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "schedule-rejects-non-cron-expression-and-unknown-job"
GROUP = "schedules"
SERVICES = ["databrew"]

VALID_CRON = "cron(15 12 * * ? *)"
UPDATED_CRON = "cron(30 6 * * ? *)"
BARE_CRON = "0 12 * * ? *"
RATE_EXPRESSION = "rate(1 hour)"


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateSchedule accepts `cron(...)` and rejects a bare cron body and `rate(1 hour)` with the same exact
    ValidationException, creating nothing; a refused UpdateSchedule (non-cron, unknown job) leaves the stored
    schedule unchanged, an empty JobNames echoes [], and a duplicate name fails with ConflictException."""
    db = ctx.client("databrew")

    schedule = ctx.unique_name("sim2real-behav-databrew-sch-")
    expected_message = (
        "Invalid schedule cron expression. Expected format: Cron(CRON_EXPRESSION)"
    )

    # ---- two rejected spellings, before anything exists
    for label, expression in (("a bare cron body", BARE_CRON), ("an EventBridge rate()", RATE_EXPRESSION)):
        code, message = _rejected(
            f"CreateSchedule with {label}",
            lambda e=expression: db.create_schedule(Name=schedule, CronExpression=e),
        )
        if code != "ValidationException":
            raise AssertionError(f"CreateSchedule with {label} raised {code}: {message!r}")
        if message != expected_message:
            raise AssertionError(
                f"CreateSchedule with {label} gave {message!r}, expected {expected_message!r}"
            )
    code, _ = _rejected(
        "describing a schedule whose creation was refused", lambda: db.describe_schedule(Name=schedule)
    )
    if code != "ResourceNotFoundException":
        raise AssertionError(f"a refused CreateSchedule left a schedule behind; describe gave {code}")

    # ---- the positive control, and a schedule with nothing to run
    db.create_schedule(Name=schedule, CronExpression=VALID_CRON)
    ctx.on_cleanup(lambda: db.delete_schedule(Name=schedule))
    described = db.describe_schedule(Name=schedule)
    if described["CronExpression"] != VALID_CRON:
        raise AssertionError(f"the accepted expression came back as {described['CronExpression']!r}")
    if "JobNames" not in described:
        raise AssertionError(
            f"a schedule created without JobNames omits the key entirely: {sorted(described)}"
        )
    if described["JobNames"] != []:
        raise AssertionError(
            f"a schedule created without JobNames reports {described['JobNames']!r}, expected []"
        )

    # ---- a rejected update must not disturb the stored expression
    code, message = _rejected(
        "UpdateSchedule with a bare cron body",
        lambda: db.update_schedule(Name=schedule, CronExpression=BARE_CRON),
    )
    if code != "ValidationException":
        raise AssertionError(f"UpdateSchedule with a bare cron raised {code}: {message!r}")
    if message != expected_message:
        raise AssertionError(f"UpdateSchedule gave {message!r}, expected {expected_message!r}")
    if db.describe_schedule(Name=schedule)["CronExpression"] != VALID_CRON:
        raise AssertionError("a refused UpdateSchedule overwrote the stored expression")

    absent_job = ctx.unique_name("sim2real-behav-databrew-nojob-")
    code, message = _rejected(
        "UpdateSchedule naming a job that does not exist",
        lambda: db.update_schedule(Name=schedule, CronExpression=UPDATED_CRON, JobNames=[absent_job]),
    )
    if code != "ValidationException":
        raise AssertionError(f"UpdateSchedule with an unknown job raised {code}: {message!r}")
    if absent_job not in message or "not found" not in message:
        raise AssertionError(f"the refusal does not name the missing job: {message!r}")
    reread = db.describe_schedule(Name=schedule)
    if reread["CronExpression"] != VALID_CRON:
        raise AssertionError("a refused UpdateSchedule changed the expression alongside the job list")
    if reread["JobNames"] != []:
        raise AssertionError(f"a refused UpdateSchedule attached the job anyway: {reread['JobNames']!r}")

    # ---- the update path does work, which is what makes the two refusals above specific
    db.update_schedule(Name=schedule, CronExpression=UPDATED_CRON)
    if db.describe_schedule(Name=schedule)["CronExpression"] != UPDATED_CRON:
        raise AssertionError("an accepted UpdateSchedule was not reflected")

    # ---- a name is claimed, not overwritten
    code, message = _rejected(
        "CreateSchedule on an existing name",
        lambda: db.create_schedule(Name=schedule, CronExpression=VALID_CRON),
    )
    if code != "ConflictException":
        raise AssertionError(f"a duplicate schedule name raised {code}: {message!r}")
    if "already exists" not in message:
        raise AssertionError(f"unexpected refusal for a duplicate name: {message!r}")
    if db.describe_schedule(Name=schedule)["CronExpression"] != UPDATED_CRON:
        raise AssertionError("the refused duplicate create overwrote the existing schedule")

    absent = ctx.unique_name("sim2real-behav-databrew-absent-")
    for label, call in (
        ("DescribeSchedule", lambda: db.describe_schedule(Name=absent)),
        ("DeleteSchedule", lambda: db.delete_schedule(Name=absent)),
    ):
        code, message = _rejected(f"{label} on a schedule that does not exist", call)
        if code != "ResourceNotFoundException":
            raise AssertionError(f"{label} on a missing schedule raised {code}: {message!r}")
        if absent not in message:
            raise AssertionError(f"{label} does not name the missing schedule: {message!r}")


def _rejected(label, fn):
    """The (code, message) of the ClientError ``fn`` must raise. An unexpected success is the
    divergence this helper exists to surface, so it raises rather than returning a sentinel."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message") or ""
    raise AssertionError(f"{label} was ACCEPTED, but real AWS rejects it")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
