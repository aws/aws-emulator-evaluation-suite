"""iam-resource-prefix-on-activity-grants-activity-ops-and-matching-token."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "iam-resource-prefix-on-activity-grants-activity-ops-and-matching-token"
GROUP = "permissions-boundaries"
SERVICES = ["iam", "stepfunctions"]

# Codes that mean "the grant (or the access key itself) has not propagated yet", not "the
# boundary failed" -- only used on the leg that expects SUCCESS.
_UNCONVERGED = frozenset({
    "AccessDeniedException", "InvalidClientTokenId", "UnrecognizedClientException",
    "SignatureDoesNotMatch",
})

_PROPAGATION_TIMEOUT_S = 120.0


def _definition(activity_arn: str) -> str:
    return json.dumps({
        "StartAt": "DoActivity",
        "States": {"DoActivity": {"Type": "Task", "Resource": activity_arn, "End": True}},
    })


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _poll_until(probe, predicate, *, timeout_s, interval_s=2.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _delete_user_and_keys(ctx, user_name: str) -> None:
    iam = ctx.client("iam")
    try:
        for key in iam.list_access_keys(UserName=user_name).get("AccessKeyMetadata", []):
            iam.delete_access_key(UserName=user_name, AccessKeyId=key["AccessKeyId"])
        for pname in iam.list_user_policies(UserName=user_name).get("PolicyNames", []):
            iam.delete_user_policy(UserName=user_name, PolicyName=pname)
        iam.delete_user(UserName=user_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _delete_role(ctx, role_name: str) -> None:
    iam = ctx.client("iam")
    try:
        for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _delete_state_machines(ctx, arns: list[str]) -> None:
    """Issue DeleteStateMachine for every arn FIRST, then wait on all of them together."""
    sfn = ctx.client("stepfunctions")
    for arn in arns:
        try:
            sfn.delete_state_machine(stateMachineArn=arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "StateMachineDoesNotExist":
                raise
    pending = set(arns)
    deadline = time.monotonic() + 180.0
    while pending:
        gone = set()
        for arn in pending:
            try:
                sfn.describe_state_machine(stateMachineArn=arn)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "StateMachineDoesNotExist":
                    raise
                gone.add(arn)
        pending -= gone
        if not pending:
            return
        if time.monotonic() >= deadline:
            raise AssertionError(f"state machine(s) still present 180s after delete: {sorted(pending)!r}")
        time.sleep(2)


def _delete_activity(ctx, arn: str) -> None:
    try:
        ctx.client("stepfunctions").delete_activity(activityArn=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ActivityDoesNotExist":
            raise


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """states:* on activity:<prefix>* allows Describe/Tag/GetActivityTask/DeleteActivity on a
    matching activity and denies a non-matching one. SendTaskSuccess carries no resource ARN, so
    AWS authorizes it against the activity the token's task belongs to, not any request field.
    """
    iam = ctx.client("iam")
    sfn = ctx.client("stepfunctions")
    account = ctx.account
    region = ctx.region

    base = ctx.unique_name("sim2real-sfnactprefix-")
    activity_match_name = f"{base}match"
    activity_other_name = ctx.unique_name("sim2real-sfnactother-") + "nomatch"

    activity_match_arn = sfn.create_activity(
        name=activity_match_name, tags=[{"key": "sim2real", "value": CHECK}]
    )["activityArn"]
    ctx.on_cleanup(lambda: _delete_activity(ctx, activity_match_arn))
    activity_other_arn = sfn.create_activity(
        name=activity_other_name, tags=[{"key": "sim2real", "value": CHECK}]
    )["activityArn"]
    ctx.on_cleanup(lambda: _delete_activity(ctx, activity_other_arn))

    exec_role_name = ctx.unique_name("sim2real-sfnactprefix-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "states.amazonaws.com"},
             "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(
        RoleName=exec_role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(ctx, exec_role_name))

    def _create_sm(name: str, activity_arn: str) -> str:
        deadline = time.monotonic() + 90.0
        while True:
            try:
                return sfn.create_state_machine(
                    name=name, definition=_definition(activity_arn), roleArn=role_arn,
                    type="STANDARD", tags=[{"key": "sim2real", "value": CHECK}],
                )["stateMachineArn"]
            except ClientError as exc:
                msg = str(exc)
                if ("not authorized to assume" not in msg
                        and "assume the provided role" not in msg) or time.monotonic() >= deadline:
                    raise
            time.sleep(2)

    sm_match_name = ctx.unique_name("sim2real-sfnactprefix-sm-")
    sm_match_arn = _create_sm(sm_match_name, activity_match_arn)
    sm_other_name = ctx.unique_name("sim2real-sfnactprefix-sm-")
    sm_other_arn = _create_sm(sm_other_name, activity_other_arn)
    ctx.on_cleanup(lambda: _delete_state_machines(ctx, [sm_match_arn, sm_other_arn]))

    user_name = ctx.unique_name("sim2real-sfnactprefix-user-")
    user_arn = iam.create_user(UserName=user_name, Tags=[{"Key": "sim2real", "Value": CHECK}])["User"]["Arn"]
    ctx.on_cleanup(lambda: _delete_user_and_keys(ctx, user_name))

    resource_pattern = f"arn:aws:states:{region}:{account}:activity:{base}*"
    iam.put_user_policy(
        UserName=user_name,
        PolicyName="prefix-scope",
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": "states:*", "Resource": resource_pattern}
            ],
        }),
    )
    key = iam.create_access_key(UserName=user_name)["AccessKey"]
    as_user = ctx.client(
        "stepfunctions",
        creds={"aws_access_key_id": key["AccessKeyId"], "aws_secret_access_key": key["SecretAccessKey"]},
    )

    # ---- BEAT 1: positive control -- DescribeActivity on the MATCHING name succeeds. ----
    box: dict[str, dict] = {}

    def _try_describe_match():
        try:
            box["desc"] = as_user.describe_activity(activityArn=activity_match_arn)
        except ClientError as exc:
            return exc.response["Error"]["Code"]
        return "UNEXPECTED_SUCCESS"

    first = _poll_until(
        _try_describe_match, lambda c: c not in _UNCONVERGED,
        timeout_s=_PROPAGATION_TIMEOUT_S,
        description="the activity-prefix grant becoming effective for DescribeActivity",
    )
    assert first == "UNEXPECTED_SUCCESS", (
        f"positive control: states:* on activity:{base}* must allow DescribeActivity "
        f"on the matching-name activity; got {first!r}"
    )
    assert box["desc"]["name"] == activity_match_name, (
        f"expected name {activity_match_name!r}, got {box['desc']['name']!r}"
    )

    def _access_denied(action: str, resource_arn: str, actual_code, actual_message) -> None:
        assert actual_code == "AccessDeniedException", (
            f"expected AccessDeniedException for {action} on {resource_arn!r}, got "
            f"{actual_code!r}: {actual_message!r}"
        )
        expected = (
            f"User: {user_arn} is not authorized to perform: {action} on resource: "
            f"{resource_arn} because no identity-based policy allows the {action} action"
        )
        assert actual_message == expected, (
            f"message for {action} was {actual_message!r}, expected {expected!r}"
        )

    # ---- BEAT 2: the NON-matching activity -- Describe and Tag denied, immediately. ----
    code, message = _error(lambda: as_user.describe_activity(activityArn=activity_other_arn))
    _access_denied("states:DescribeActivity", activity_other_arn, code, message)

    code, message = _error(
        lambda: as_user.tag_resource(
            resourceArn=activity_other_arn, tags=[{"key": "k", "value": "v"}]
        )
    )
    _access_denied("states:TagResource", activity_other_arn, code, message)

    # ---- BEAT 3: TagResource on the MATCHING activity succeeds, and the effect is real. ----
    as_user.tag_resource(resourceArn=activity_match_arn, tags=[{"key": "k", "value": "v"}])
    tags_now = {
        t["key"]: t["value"] for t in sfn.list_tags_for_resource(resourceArn=activity_match_arn)["tags"]
    }
    assert tags_now.get("k") == "v", f"tag not visible after TagResource: {tags_now!r}"

    # ---- BEAT 4: start one execution per state machine so each activity has a pending task,
    # then GetActivityTask as the restricted user. ----
    exec_match_arn = sfn.start_execution(stateMachineArn=sm_match_arn, input="{}")["executionArn"]
    ctx.on_cleanup(lambda: sfn.stop_execution(executionArn=exec_match_arn))
    exec_other_arn = sfn.start_execution(stateMachineArn=sm_other_arn, input="{}")["executionArn"]
    ctx.on_cleanup(lambda: sfn.stop_execution(executionArn=exec_other_arn))

    match_task = as_user.get_activity_task(activityArn=activity_match_arn)
    assert match_task.get("taskToken"), (
        f"GetActivityTask on the matching activity returned no task: {match_task!r}"
    )

    code, message = _error(lambda: as_user.get_activity_task(activityArn=activity_other_arn))
    _access_denied("states:GetActivityTask", activity_other_arn, code, message)

    # The non-matching activity's task is fetched by the ADMIN identity, so its token exists
    # for the next beat without ever granting the restricted user activity:GetActivityTask on it.
    other_task = sfn.get_activity_task(activityArn=activity_other_arn)
    assert other_task.get("taskToken"), (
        f"GetActivityTask (admin) on the non-matching activity returned no task: {other_task!r}"
    )

    # ---- BEAT 5: SendTaskSuccess carries no resource ARN in its request at all -- AWS must
    # resolve it to the activity the TOKEN belongs to. The restricted user succeeds on the
    # matching token and is denied on the other, even though the call shape is identical. ----
    as_user.send_task_success(taskToken=match_task["taskToken"], output="{}")
    match_final = _poll_until(
        lambda: sfn.describe_execution(executionArn=exec_match_arn),
        lambda d: d["status"] != "RUNNING", timeout_s=60.0,
        description="the matching execution reaching a terminal state after SendTaskSuccess",
    )
    assert match_final["status"] == "SUCCEEDED", (
        f"expected SUCCEEDED after SendTaskSuccess on the matching token, got "
        f"{match_final['status']!r}"
    )

    code, message = _error(
        lambda: as_user.send_task_success(taskToken=other_task["taskToken"], output="{}")
    )
    assert code == "AccessDeniedException", (
        f"SendTaskSuccess for a token belonging to the non-matching activity must be denied; "
        f"got {code!r}: {message!r}"
    )
    expected = (
        f"User: {user_arn} is not authorized to perform: states:SendTaskSuccess on resource: "
        f"{activity_other_arn} because no identity-based policy allows the "
        f"states:SendTaskSuccess action"
    )
    assert message == expected, f"message was {message!r}, expected {expected!r}"

    still_running = sfn.describe_execution(executionArn=exec_other_arn)
    assert still_running["status"] == "RUNNING", (
        f"the denied SendTaskSuccess must have no effect; status is {still_running['status']!r}"
    )
    sfn.send_task_success(taskToken=other_task["taskToken"], output="{}")

    # ---- BEAT 6: DeleteActivity -- denied on the non-matching activity, then it succeeds on
    # the matching one and the activity is actually gone. ----
    code, message = _error(lambda: as_user.delete_activity(activityArn=activity_other_arn))
    _access_denied("states:DeleteActivity", activity_other_arn, code, message)

    as_user.delete_activity(activityArn=activity_match_arn)

    def _probe_gone():
        try:
            sfn.describe_activity(activityArn=activity_match_arn)
        except ClientError as exc:
            return exc.response["Error"]["Code"]
        return "STILL_PRESENT"

    final_code = _poll_until(
        _probe_gone, lambda c: c != "STILL_PRESENT", timeout_s=60.0,
        description="the deleted activity disappearing from DescribeActivity",
    )
    assert final_code == "ActivityDoesNotExist", (
        f"expected ActivityDoesNotExist after DeleteActivity, got {final_code!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
