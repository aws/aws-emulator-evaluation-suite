"""sfn-service-level-only-actions-succeed-resource-scoped-actions-denied."""
from __future__ import annotations

import json
import time

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sfn-service-level-only-actions-succeed-resource-scoped-actions-denied"
GROUP = "overly_permissive"
SERVICES = ["stepfunctions"]

_SESSION_NAME = "sim2real-behav-restricted"

_STATES_TRUST = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Principal": {"Service": "states.amazonaws.com"},
        "Action": "sts:AssumeRole",
    }],
})
_DEFINITION = json.dumps({"StartAt": "Pass", "States": {"Pass": {"Type": "Pass", "End": True}}})


@tags(
    "axis:rejection",
    "concern:negative-classes",
    "concern:representation",
    "cap:c7",
    "plane:control",
)
def run(ctx) -> None:
    """A policy scoped to the account-wide ARN pattern lets List/Create/UpdateStateMachine
    succeed, but a resource-scoped action on the very resource that same caller just created
    (DescribeStateMachine, StartExecution) is still denied.
    """
    sfn = ctx.client("stepfunctions")
    iam = ctx.client("iam")
    account_id = ctx.account

    exec_role_arn = _create_role(ctx, "sim2real-behav-execrole-", _STATES_TRUST)

    caller_role_name = ctx.unique_name("sim2real-behav-restrictedcaller-")
    caller_role_arn = iam.create_role(
        RoleName=caller_role_name,
        AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"AWS": account_id},
                "Action": "sts:AssumeRole",
            }],
        }),
        Description="sim2real-behav sfn authorisation-boundary role",
        Tags=[{"Key": "sim2real", "Value": "1"}],
    )["Role"]["Arn"]

    def _delete_caller_role():
        for pname in iam.list_role_policies(RoleName=caller_role_name).get("PolicyNames", []):
            try:
                iam.delete_role_policy(RoleName=caller_role_name, PolicyName=pname)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
        iam.delete_role(RoleName=caller_role_name)

    ctx.on_cleanup(_delete_caller_role)

    account_wildcard = f"arn:aws:states:{ctx.region}:{account_id}:*"
    iam.put_role_policy(
        RoleName=caller_role_name,
        PolicyName=f"{caller_role_name}-policy",
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": [
                        "states:ListStateMachines",
                        "states:ListActivities",
                        "states:CreateStateMachine",
                        "states:CreateActivity",
                        "states:UpdateStateMachine",
                    ],
                    "Resource": account_wildcard,
                },
                # Only enough to let CreateStateMachine itself through; the claim under test is
                # about the states: actions, not about iam:PassRole.
                {"Effect": "Allow", "Action": "iam:PassRole", "Resource": exec_role_arn},
            ],
        }),
    )

    restricted_sfn = _assume_as_client(ctx, "stepfunctions", caller_role_arn)

    # The service-level-only actions succeed under the account-wildcard Resource.
    _retry_while_denied(lambda: restricted_sfn.list_state_machines())
    restricted_sfn.list_activities()

    sm_name = ctx.unique_name("sim2real-behav-sm-")
    sm_arn = restricted_sfn.create_state_machine(
        name=sm_name, definition=_DEFINITION, roleArn=exec_role_arn,
    )["stateMachineArn"]
    # The creating caller cannot Describe/Delete the very resource it just made (see below), so
    # the main ctx credentials own the teardown.
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=sm_arn))

    activity_name = ctx.unique_name("sim2real-behav-activity-")
    activity_arn = restricted_sfn.create_activity(name=activity_name)["activityArn"]
    ctx.on_cleanup(lambda: sfn.delete_activity(activityArn=activity_arn))

    updated_definition = json.dumps({
        "Comment": "updated-by-service-level-only-caller",
        "StartAt": "Pass",
        "States": {"Pass": {"Type": "Pass", "End": True}},
    })
    restricted_sfn.update_state_machine(stateMachineArn=sm_arn, definition=updated_definition)
    updated = sfn.describe_state_machine(stateMachineArn=sm_arn)
    assert updated["definition"] == updated_definition, (
        f"UpdateStateMachine under the account-wildcard policy did not land: "
        f"{updated['definition']!r}"
    )

    # Resource-scoped actions on the SAME resource this caller just created are denied: the
    # grant above names no resource-level permission for them.
    partition = caller_role_arn.split(":")[1]
    assumed_arn = f"arn:{partition}:sts::{account_id}:assumed-role/{caller_role_name}/{_SESSION_NAME}"

    code, message = _error(lambda: restricted_sfn.describe_state_machine(stateMachineArn=sm_arn))
    assert code == "AccessDeniedException", (
        f"DescribeStateMachine under a service-level-only policy returned {code}: {message!r}, "
        f"expected AccessDeniedException"
    )
    expected = (
        f"User: {assumed_arn} is not authorized to perform: states:DescribeStateMachine on "
        f"resource: {sm_arn} because no identity-based policy allows the "
        "states:DescribeStateMachine action"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    code, message = _error(lambda: restricted_sfn.start_execution(stateMachineArn=sm_arn))
    assert code == "AccessDeniedException", (
        f"StartExecution under a service-level-only policy returned {code}: {message!r}, "
        f"expected AccessDeniedException"
    )
    expected = (
        f"User: {assumed_arn} is not authorized to perform: states:StartExecution on "
        f"resource: {sm_arn} because no identity-based policy allows the "
        "states:StartExecution action"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Positive control: the main (unrestricted) credentials can still Describe it, proving the
    # resource exists and the denial above is an authorization decision, not a missing resource.
    control = sfn.describe_state_machine(stateMachineArn=sm_arn)
    assert control["stateMachineArn"] == sm_arn, (
        f"positive control described {control.get('stateMachineArn')!r}, expected {sm_arn!r}"
    )


def _create_role(ctx, prefix, trust_policy):
    iam = ctx.client("iam")
    role_name = ctx.unique_name(prefix)
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=trust_policy,
        Description="sim2real-behav sfn authorisation-boundary role",
        Tags=[{"Key": "sim2real", "Value": "1"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return role_arn


def _assume_as_client(ctx, service, role_arn, *, timeout_s=90.0):
    """A ctx client for `service` signed with `role_arn`'s credentials, same target as ctx's.
    Assuming a brand-new role fails until IAM propagates, so the retry is bounded."""
    sts = ctx.client("sts")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            creds = sts.assume_role(
                RoleArn=role_arn, RoleSessionName=_SESSION_NAME
            )["Credentials"]
        except ClientError as exc:
            last = exc
            time.sleep(2)
            continue
        return ctx.client(
            service,
            config=Config(retries={"max_attempts": 2}),
            creds={
                "aws_access_key_id": creds["AccessKeyId"],
                "aws_secret_access_key": creds["SecretAccessKey"],
                "aws_session_token": creds["SessionToken"],
            },
        )
    raise AssertionError(f"could not assume {role_arn!r} within {timeout_s}s: {last!r}")


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _retry_while_denied(fn, *, timeout_s=360.0):
    """The result of `fn`, retried while the freshly attached policy has not propagated
    (AccessDeniedException) or a just-minted session token is not yet recognised everywhere
    (UnrecognizedClientException); any other error or a timeout is a real failure."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code not in ("AccessDeniedException", "UnrecognizedClientException"):
                raise
            last = exc
            time.sleep(2)
    raise AssertionError(f"still denied after {timeout_s}s of IAM propagation: {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
