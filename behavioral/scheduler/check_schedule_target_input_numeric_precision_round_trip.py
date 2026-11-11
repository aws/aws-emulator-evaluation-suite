"""schedule-target-input-numeric-precision-round-trip."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "schedule-target-input-numeric-precision-round-trip"
GROUP = "representation"
SERVICES = ["scheduler"]

_NUMERIC_INPUT = (
    '{"big_int": 123456789012345678901234567890, '
    '"pi": 3.14159265358979323846, '
    '"tiny": 0.000000000000123456, '
    '"neg_exp": -1.5e-300}'
)


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """High-precision float/large-int literals in Target.Input survive create->get unmodified.

    Target.Input is an opaque string, so even literals overflowing int64/float64 come back verbatim."""
    scheduler = ctx.client("scheduler")
    account_id = _account_id(ctx)
    role_arn = _create_execution_role(ctx)
    name = ctx.unique_name("sim2real-behav-sched-")

    _create_schedule_with_retry(
        scheduler,
        Name=name,
        ScheduleExpression="rate(1 hour)",
        State="DISABLED",
        FlexibleTimeWindow={"Mode": "OFF"},
        Target=_fake_target(ctx, account_id, role_arn, _NUMERIC_INPUT),
    )
    ctx.on_cleanup(lambda: _delete_schedule_if_present(scheduler, name))

    got = scheduler.get_schedule(Name=name)
    assert got["Target"]["Input"] == _NUMERIC_INPUT, (
        f"numeric Input payload was reformatted: {got['Target']['Input']!r} != {_NUMERIC_INPUT!r}"
    )

    scheduler.delete_schedule(Name=name)
    try:
        scheduler.get_schedule(Name=name)
        raise AssertionError(f"GetSchedule still returns {name!r} after DeleteSchedule")
    except scheduler.exceptions.ResourceNotFoundException as exc:
        got_message = exc.response["Error"].get("Message")
        expected = f"Schedule {name} does not exist."
        assert got_message == expected, f"expected {expected!r}, got {got_message!r}"


def _account_id(ctx) -> str:
    return ctx.client("sts").get_caller_identity()["Account"]


def _create_execution_role(ctx) -> str:
    import json

    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-sched-role-")
    trust_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "scheduler.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
    )
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=trust_policy,
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )

    def _cleanup():
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    return role["Role"]["Arn"]


def _create_schedule_with_retry(scheduler, **kwargs):
    import time

    from botocore.exceptions import ClientError

    deadline = time.time() + 45
    last_err = None
    while time.time() < deadline:
        try:
            return scheduler.create_schedule(**kwargs)
        except ClientError as err:
            code = err.response["Error"]["Code"]
            message = err.response["Error"].get("Message", "")
            if code == "ValidationException" and "assume" in message.lower():
                last_err = err
                time.sleep(3)
                continue
            raise
    raise last_err


def _delete_schedule_if_present(scheduler, name: str) -> None:
    try:
        scheduler.delete_schedule(Name=name)
    except scheduler.exceptions.ResourceNotFoundException:
        pass


def _fake_target(ctx, account_id: str, role_arn: str, input_payload: str) -> dict:
    # The target ARN need not resolve to a real queue for CreateSchedule to succeed, and
    # Input content is not validated at creation time (only format), but RoleArn's trust
    # policy IS validated: it must allow scheduler.amazonaws.com to assume it.
    return {
        "Arn": f"arn:aws:sqs:{ctx.region}:{account_id}:sim2real-behav-fake-queue",
        "RoleArn": role_arn,
        "Input": input_payload,
    }


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
