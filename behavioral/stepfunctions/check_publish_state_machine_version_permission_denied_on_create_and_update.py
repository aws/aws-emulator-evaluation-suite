"""publish-state-machine-version-permission-denied-on-create-and-update."""
from __future__ import annotations

import json
import time

from botocore.credentials import Credentials
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "publish-state-machine-version-permission-denied-on-create-and-update"
GROUP = "negative-classes"
SERVICES = ["stepfunctions", "iam", "sts"]

_SESSION = "sim2real-sfnpub"

_SFN_TRUST_POLICY = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Principal": {"Service": "states.amazonaws.com"},
        "Action": "sts:AssumeRole",
    }],
})

_DEF_V1 = {"StartAt": "Initial", "States": {"Initial": {"Type": "Pass", "End": True}}}
_DEF_V2 = {"StartAt": "Updated", "States": {"Updated": {"Type": "Pass", "End": True}}}


def _create_exec_role(ctx) -> str:
    """The role Step Functions assumes to run the state machine; needs no permissions for a
    Pass-only definition."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-sfn-exec-")
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=_SFN_TRUST_POLICY,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return role_arn


def _create_caller_role(ctx, exec_role_arn: str) -> dict:
    """A caller identity allowed every states:* action this check needs except
    states:PublishStateMachineVersion, so a publish=true request fails on that one action."""
    iam = ctx.client("iam")
    account_id = ctx.account
    role_name = ctx.unique_name("sim2real-sfn-caller-")
    trust = {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
        "Action": "sts:AssumeRole",
    }]}
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "states:CreateStateMachine",
                    "states:UpdateStateMachine",
                    "states:DescribeStateMachine",
                    "states:DeleteStateMachine",
                ],
                "Resource": "*",
            },
            {"Effect": "Allow", "Action": "iam:PassRole", "Resource": exec_role_arn},
        ],
    }
    iam.put_role_policy(
        RoleName=role_name, PolicyName="caller-without-publish", PolicyDocument=json.dumps(policy)
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="caller-without-publish"))
    return {"arn": role_arn, "session_arn": f"arn:aws:sts::{account_id}:assumed-role/{role_name}/{_SESSION}"}


def _assume(ctx, role_arn: str, timeout_s: float = 120.0) -> Credentials:
    """Assume role_arn, retrying the AccessDenied a brand-new role's trust gives while IAM
    propagates; IAM exposes no condition to poll for that, so the bounded retry is the wait."""
    sts = ctx.client("sts")
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            c = sts.assume_role(RoleArn=role_arn, RoleSessionName=_SESSION)["Credentials"]
            return Credentials(c["AccessKeyId"], c["SecretAccessKey"], c["SessionToken"])
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDenied" or time.monotonic() > deadline:
                raise
            time.sleep(3)


def _creds_dict(creds: Credentials) -> dict:
    return {
        "aws_access_key_id": creds.access_key,
        "aws_secret_access_key": creds.secret_key,
        "aws_session_token": creds.token,
    }


def _error(fn, *, retry_access_denied_propagation: str):
    """Call fn(); return its (code, message), retrying only the named propagation message.

    An unexpected success raises."""
    deadline = time.monotonic() + 90.0
    while True:
        try:
            result = fn()
        except ClientError as exc:
            err = exc.response.get("Error", {})
            code, message = err.get("Code"), err.get("Message")
            if (
                code == "AccessDeniedException"
                and message == retry_access_denied_propagation
                and time.monotonic() < deadline
            ):
                time.sleep(3)
                continue
            return code, message
        raise AssertionError(f"expected a ClientError, but the call succeeded: {result!r}")


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A caller allowed CreateStateMachine and UpdateStateMachine but denied
    states:PublishStateMachineVersion is refused AccessDeniedException whenever publish=true,
    and the identical call with publish=false succeeds for both operations.
    """
    admin_sfn = ctx.client("stepfunctions")
    exec_role_arn = _create_exec_role(ctx)
    caller = _create_caller_role(ctx, exec_role_arn)
    creds = _assume(ctx, caller["arn"])
    denied_sfn = ctx.client("stepfunctions", creds=_creds_dict(creds))

    propagation = (
        "Neither the global service principal states.amazonaws.com, nor the regional one is "
        "authorized to assume the provided role."
    )

    # CreateStateMachine with publish=true is denied on states:PublishStateMachineVersion.
    name = ctx.unique_name("sim2real-behav-sm-pubdenied-")
    code, message = _error(
        lambda: denied_sfn.create_state_machine(
            name=name, definition=json.dumps(_DEF_V1), roleArn=exec_role_arn, publish=True,
        ),
        retry_access_denied_propagation=propagation,
    )
    assert code == "AccessDeniedException", f"create publish=true: expected AccessDeniedException, got {code!r}"
    would_be_arn = f"arn:aws:states:{ctx.region}:{ctx.account}:stateMachine:{name}"
    expected = (
        f"User: {caller['session_arn']} is not authorized to perform: "
        f"states:PublishStateMachineVersion on resource: {would_be_arn} because no "
        "identity-based policy allows the states:PublishStateMachineVersion action"
    )
    assert message == expected, f"create publish=true: unexpected message {message!r}"

    names = [sm["name"] for sm in admin_sfn.list_state_machines(maxResults=1000).get("stateMachines", [])]
    assert name not in names, f"denied create publish=true must not have created {name!r}"

    # Positive control: the same caller, same definition, publish=false succeeds.
    created = denied_sfn.create_state_machine(
        name=name, definition=json.dumps(_DEF_V1), roleArn=exec_role_arn, publish=False,
    )
    arn = created["stateMachineArn"]
    ctx.on_cleanup(lambda: admin_sfn.delete_state_machine(stateMachineArn=arn))
    assert created.get("stateMachineVersionArn") is None, (
        f"publish=false create must not publish a version, got {created.get('stateMachineVersionArn')!r}"
    )
    described = admin_sfn.describe_state_machine(stateMachineArn=arn)
    assert described["status"] == "ACTIVE", f"expected status ACTIVE, got {described['status']!r}"

    # UpdateStateMachine with publish=true is denied the same way.
    code, message = _error(
        lambda: denied_sfn.update_state_machine(
            stateMachineArn=arn, definition=json.dumps(_DEF_V2), publish=True,
        ),
        retry_access_denied_propagation=propagation,
    )
    assert code == "AccessDeniedException", f"update publish=true: expected AccessDeniedException, got {code!r}"
    expected = (
        f"User: {caller['session_arn']} is not authorized to perform: "
        f"states:PublishStateMachineVersion on resource: {arn} because no identity-based policy "
        "allows the states:PublishStateMachineVersion action"
    )
    assert message == expected, f"update publish=true: unexpected message {message!r}"

    unchanged = admin_sfn.describe_state_machine(stateMachineArn=arn)
    assert json.loads(unchanged["definition"]) == _DEF_V1, (
        f"denied update publish=true must leave the definition unchanged, got "
        f"{json.loads(unchanged['definition'])!r}"
    )

    # Positive control: the same caller, same definition, publish=false succeeds.
    updated = denied_sfn.update_state_machine(
        stateMachineArn=arn, definition=json.dumps(_DEF_V2), publish=False,
    )
    assert updated.get("stateMachineVersionArn") is None, (
        f"publish=false update must not publish a version, got {updated.get('stateMachineVersionArn')!r}"
    )
    final = _poll_until(
        lambda: admin_sfn.describe_state_machine(stateMachineArn=arn),
        lambda r: json.loads(r["definition"]).get("StartAt") == "Updated",
        timeout_s=30.0,
        description="updated definition visible",
    )
    assert final["revisionId"] == updated["revisionId"], (
        "describe revisionId must match the update's revisionId"
    )


def _poll_until(probe, predicate, *, timeout_s, interval_s=2.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
