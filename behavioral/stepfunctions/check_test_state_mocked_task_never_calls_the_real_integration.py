"""test-state-mocked-task-never-calls-the-real-integration."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "test-state-mocked-task-never-calls-the-real-integration"
GROUP = "definition_semantics"
SERVICES = ["stepfunctions"]

_TRUST = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "states.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
)
_DEFINITION = json.dumps(
    {
        "Type": "Task",
        "Resource": "arn:aws:states:::aws-sdk:sfn:createActivity",
        "Parameters": {"Name.$": "$.name"},
        "End": True,
    }
)


def _undo(delete, *gone: str):
    """A cleanup whose delete raises unless the resource reports one of ``gone``."""

    def apply() -> None:
        try:
            delete()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in gone:
                return
            raise

    return apply


def _once_assumable(call, *, budget_s: float = 120.0):
    """``call()``, retrying while a freshly created role is not yet usable by the service."""
    deadline = time.monotonic() + budget_s
    while True:
        try:
            return call()
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code not in ("AccessDeniedException", "InvalidArn") or time.monotonic() > deadline:
                raise
            time.sleep(5)


def _after_trust_propagates(call, *, budget_s: float = 180.0) -> dict:
    """``call()``'s answer once the service can assume the role the check just created.

    No API reports when a new trust policy becomes effective, so the task's own failure cause is
    the only signal to wait on; the last answer is returned either way, for the caller to grade.
    """
    deadline = time.monotonic() + budget_s
    while True:
        answer = _once_assumable(call)
        waiting = answer.get("status") == "FAILED" and "not authorized to assume" in (
            answer.get("cause") or ""
        )
        if not waiting or time.monotonic() > deadline:
            return answer
        time.sleep(5)


def _failure(call) -> tuple[str, str]:
    """The ``(code, message)`` ``call()`` is refused with; an unexpected success raises."""
    try:
        answer = call()
    except ClientError as exc:
        error = exc.response["Error"]
        return error["Code"], error.get("Message") or ""
    raise AssertionError(f"expected the call to be refused, but it returned {answer!r}")


def _sighting(sfn, activity_arn: str) -> list[str]:
    """``[name]`` when the activity exists, else ``[]``."""
    try:
        return [sfn.describe_activity(activityArn=activity_arn)["name"]]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ActivityDoesNotExist":
            return []
        raise


def _visible_after(observe, *, budget_s: float = 120.0) -> float:
    """Seconds until ``observe()`` first returns a sighting: the positive control's latency."""
    start = time.monotonic()
    while True:
        if observe():
            return time.monotonic() - start
        if time.monotonic() - start > budget_s:
            raise AssertionError(f"the real integration's effect was unobservable in {budget_s}s")
        time.sleep(1)


def _sightings_over(observe, latency_s: float, *, floor_s: float = 10.0) -> list[str]:
    """Every sighting ``observe()`` returned over three times the positive control's latency."""
    deadline = time.monotonic() + max(floor_s, 3.0 * latency_s)
    seen: list[str] = []
    while True:
        seen.extend(observe())
        if time.monotonic() >= deadline:
            return seen
        time.sleep(1)


def _names(sfn) -> set[str]:
    """Every activity name the account lists."""
    pages = sfn.get_paginator("list_activities").paginate()
    return {item["name"] for page in pages for item in page["activities"]}


@tags(
    "axis:negative-delivery",
    "cap:c3",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """A mocked Task under TestState stands in for the integration instead of performing it: the
    same definition run without a mock really creates the resource its Resource names, and the
    mocked run returns the mock while the resource is never created.

    Reference: https://docs.aws.amazon.com/step-functions/latest/dg/test-state-isolation.html
    """
    sfn = ctx.client("stepfunctions")
    iam = ctx.client("iam")

    performed = ctx.unique_name("sim2real-behav-sfn-performed-")
    mocked = ctx.unique_name("sim2real-behav-sfn-mocked-")
    prefix = f"arn:aws:states:{ctx.region}:{ctx.account}:activity:"
    performed_arn, mocked_arn = prefix + performed, prefix + mocked

    role_name = ctx.unique_name("sim2real-behav-sfn-mock-")
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=_TRUST,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(_undo(lambda: iam.delete_role(RoleName=role_name), "NoSuchEntity"))

    # Both names are grantable, so a target that performs the mocked call would create the activity
    # rather than be denied it: absence below can only mean the mock replaced the integration.
    policy_name = "create-activity"
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "states:CreateActivity",
                        "Resource": [performed_arn, mocked_arn],
                    }
                ],
            }
        ),
    )
    ctx.on_cleanup(
        _undo(
            lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name),
            "NoSuchEntity",
        )
    )

    for arn in (performed_arn, mocked_arn):
        ctx.on_cleanup(_undo(lambda target=arn: sfn.delete_activity(activityArn=target)))

    real = _after_trust_propagates(
        lambda: sfn.test_state(
            definition=_DEFINITION,
            roleArn=role_arn,
            input=json.dumps({"name": performed}),
            inspectionLevel="INFO",
        )
    )
    assert real["status"] == "SUCCEEDED", (
        f"the unmocked run reported {real['status']!r}, error {real.get('error')!r}, "
        f"cause {real.get('cause')!r}"
    )
    assert json.loads(real["output"])["ActivityArn"] == performed_arn, (
        f"the unmocked run returned {real['output']!r}, which does not name the activity it created"
    )
    latency_s = _visible_after(lambda: _sighting(sfn, performed_arn))

    mock_result = json.dumps({"ActivityArn": mocked_arn, "CreationDate": 1})
    stubbed = sfn.test_state(
        definition=_DEFINITION,
        input=json.dumps({"name": mocked}),
        inspectionLevel="INFO",
        mock={"result": mock_result, "fieldValidationMode": "NONE"},
    )
    assert stubbed["status"] == "SUCCEEDED", (
        f"the mocked run reported {stubbed['status']!r}, error {stubbed.get('error')!r}, "
        f"cause {stubbed.get('cause')!r}"
    )
    assert json.loads(stubbed["output"]) == json.loads(mock_result), (
        f"the mocked run returned {stubbed['output']!r} instead of the mock it was handed"
    )

    seen = _sightings_over(lambda: _sighting(sfn, mocked_arn), latency_s)
    assert seen == [], f"the mocked integration created {len(seen)} activity: {seen!r}"

    code, message = _failure(lambda: sfn.describe_activity(activityArn=mocked_arn))
    assert (code, message) == ("ActivityDoesNotExist", f"Activity Does Not Exist: '{mocked_arn}'"), (
        f"reading the activity the mock stood in for gave {(code, message)!r}"
    )

    listed = _names(sfn)
    assert performed in listed, f"the activity the unmocked run created is not listed: {performed!r}"
    assert mocked not in listed, f"the mocked run's activity name is listed: {mocked!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
