"""create-describe-roundtrip."""
from __future__ import annotations

import datetime
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-describe-roundtrip"
GROUP = 'state_machine_lifecycle'
SERVICES = ['stepfunctions']

_ROLE_ARNS = {}


def _execution_role_arn(ctx):
    """Create one Step Functions execution role per check run and register its cleanup."""
    key = id(ctx)
    if key in _ROLE_ARNS:
        return _ROLE_ARNS[key]
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-sfnrole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "states.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    ctx.on_cleanup(lambda: _ROLE_ARNS.pop(key, None))
    _ROLE_ARNS[key] = arn
    return arn


def _create_sm_retrying(sfn, **kwargs):
    """CreateStateMachine, retried while a just-created role is still propagating in IAM."""
    deadline = time.monotonic() + 60.0
    while True:
        try:
            return sfn.create_state_machine(**kwargs)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException" or time.monotonic() > deadline:
                raise
            time.sleep(3)


def _create_state_machine(ctx, definition, *, name=None, sm_type="STANDARD"):
    sfn = ctx.client("stepfunctions")
    name = name or ctx.unique_name("sim2real-behav-sm-")
    arn = _create_sm_retrying(
        sfn,
        name=name,
        definition=json.dumps(definition),
        roleArn=_execution_role_arn(ctx),
        type=sm_type,
    )["stateMachineArn"]
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
    return arn

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateStateMachine -> DescribeStateMachine returns consistent fields."""
    sfn = ctx.client("stepfunctions")
    definition = {
        "StartAt": "Pass",
        "States": {"Pass": {"Type": "Pass", "End": True}},
    }
    role_arn = _execution_role_arn(ctx)
    before = datetime.datetime.now(datetime.timezone.utc)
    arn = _create_state_machine(ctx, definition)
    resp = sfn.describe_state_machine(stateMachineArn=arn)
    after = datetime.datetime.now(datetime.timezone.utc)
    assert resp["stateMachineArn"] == arn, (
        f"expected stateMachineArn {arn!r}, got {resp.get('stateMachineArn')!r}"
    )
    assert resp["status"] == "ACTIVE", f"expected status ACTIVE, got {resp.get('status')!r}"
    assert resp["type"] == "STANDARD", f"expected type STANDARD, got {resp.get('type')!r}"
    parsed_def = json.loads(resp["definition"])
    assert parsed_def["StartAt"] == "Pass", (
        f"expected StartAt Pass in echoed definition, got {parsed_def.get('StartAt')!r}"
    )
    assert resp["roleArn"] == role_arn, f"expected roleArn {role_arn!r}, got {resp.get('roleArn')!r}"
    creation_date = resp["creationDate"]
    assert before <= creation_date <= after, (
        f"expected creationDate in [{before}, {after}], got {creation_date}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
