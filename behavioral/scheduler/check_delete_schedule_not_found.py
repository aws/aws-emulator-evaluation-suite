"""delete-schedule-not-found."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-schedule-not-found"
GROUP = 'error-semantics'
SERVICES = ['scheduler']

def _error(fn):
    """Call fn(); return the (code, message) it is refused with. An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a refusal, but the call SUCCEEDED and returned {result!r}")


def _create_scheduler_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-sched-role-")
    trust = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "scheduler.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    })
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=trust,
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["Role"]["Arn"]

    def _cleanup():
        try:
            iam.delete_role_policy(RoleName=role_name, PolicyName="sched-target")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup)
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="sched-target",
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": "*"}],
        }),
    )
    return role_arn


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteSchedule on a nonexistent schedule raises ResourceNotFoundException; the same name
    was first created and deleted successfully, so the rejection is specific to absence."""
    sch = ctx.client("scheduler")
    account = ctx.client("sts").get_caller_identity()["Account"]
    role_arn = _create_scheduler_role(ctx)
    name = ctx.unique_name("sim2real-behav-" + "no-such-sched-")

    # IAM role trust is eventually consistent; retry CreateSchedule briefly.
    deadline = time.monotonic() + 60.0
    last_exc = None
    created = False
    while time.monotonic() < deadline:
        try:
            sch.create_schedule(
                Name=name,
                ScheduleExpression="rate(10 minutes)",
                FlexibleTimeWindow={"Mode": "OFF"},
                Target={
                    "Arn": f"arn:aws:sqs:{ctx.region}:{account}:sim2real-behav-placeholder-target",
                    "RoleArn": role_arn,
                },
            )
            created = True
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] in ("ValidationException", "AccessDeniedException"):
                last_exc = exc
                time.sleep(3)
                continue
            raise
    if not created:
        raise AssertionError(f"could not create positive-control schedule: {last_exc}")

    # Positive control: the schedule exists and DeleteSchedule works against it.
    got = sch.get_schedule(Name=name)
    assert got["Name"] == name, f"expected positive control schedule to exist, got {got}"
    sch.delete_schedule(Name=name)
    expected = f"Schedule {name} does not exist."
    gone = _error(lambda: sch.get_schedule(Name=name))
    assert gone == ("ResourceNotFoundException", expected), (
        f"positive control: expected the just-deleted schedule to be independently gone, got {gone!r}"
    )

    # Subject: deleting the now-nonexistent schedule again raises the specific not-found code.
    code, message = _error(lambda: sch.delete_schedule(Name=name))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    assert message == expected, f"expected message {expected!r}, got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
