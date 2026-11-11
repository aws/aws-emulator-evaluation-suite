"""update-state-machine."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-state-machine"
GROUP = 'state_machine_lifecycle'
SERVICES = ['stepfunctions']

_SFN_TRUST_POLICY = json.dumps(
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

_SFN_INLINE_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["states:StartExecution", "states:DescribeExecution", "states:StopExecution"],
                "Resource": "*",
            }
        ],
    }
)


def _create_sfn_role(ctx):
    """Create an execution role Step Functions can assume; it is deleted at teardown."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-sfn-role-")
    arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=_SFN_TRUST_POLICY,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]["Arn"]

    def _delete_role():
        for fn in (
            lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="sfn-inline"),
            lambda: iam.delete_role(RoleName=role_name),
        ):
            try:
                fn()
            except ClientError as exc:
                if exc.response.get("Error", {}).get("Code") != "NoSuchEntity":
                    raise

    ctx.on_cleanup(_delete_role)
    iam.put_role_policy(RoleName=role_name, PolicyName="sfn-inline", PolicyDocument=_SFN_INLINE_POLICY)
    return arn


def _await_role(fn, *, timeout_s=90.0):
    """Call fn(), retrying AccessDeniedException while a new role's trust policy propagates."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "AccessDeniedException" or time.monotonic() > deadline:
                raise
            time.sleep(5)


def _create_state_machine(ctx, definition, *, name=None, sm_type="STANDARD"):
    sfn = ctx.client("stepfunctions")
    name = name or ctx.unique_name("sim2real-behav-sm-")
    role_arn = _create_sfn_role(ctx)
    arn = _await_role(lambda: sfn.create_state_machine(
        name=name,
        definition=json.dumps(definition),
        roleArn=role_arn,
        type=sm_type,
    ))["stateMachineArn"]
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
    return arn

def _poll_until(probe, predicate, *, timeout_s=30, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateStateMachine changes the definition visible via Describe and bumps revisionId."""
    sfn = ctx.client("stepfunctions")
    definition_v1 = {
        "StartAt": "A",
        "States": {"A": {"Type": "Pass", "Result": "v1", "End": True}},
    }
    arn = _create_state_machine(ctx, definition_v1)
    before = sfn.describe_state_machine(stateMachineArn=arn)
    before_rev = before.get("revisionId")

    definition_v2 = {
        "StartAt": "B",
        "States": {"B": {"Type": "Pass", "Result": "v2", "End": True}},
    }
    sfn.update_state_machine(stateMachineArn=arn, definition=json.dumps(definition_v2))

    resp = _poll_until(
        lambda: sfn.describe_state_machine(stateMachineArn=arn),
        lambda r: json.loads(r["definition"]).get("StartAt") == "B",
        timeout_s=30,
        interval_s=1.0,
        description="updated definition visible on describe",
    )
    parsed = json.loads(resp["definition"])
    assert parsed["StartAt"] == "B", f"expected updated StartAt 'B', got {parsed.get('StartAt')!r}"

    after_rev = resp.get("revisionId")
    assert after_rev, "expected a non-blank revisionId on describe after update"
    assert after_rev != before_rev, (
        f"revisionId must change after update: before={before_rev!r} after={after_rev!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
