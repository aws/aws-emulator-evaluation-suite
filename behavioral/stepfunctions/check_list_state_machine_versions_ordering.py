"""list-state-machine-versions-ordering."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-state-machine-versions-ordering"
GROUP = 'update_versioning'
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
        tags=[{"key": "sim2real", "value": "1"}],
    )["stateMachineArn"]
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
    return arn


def _pass_def(n):
    return {"StartAt": "P", "States": {"P": {"Type": "Pass", "Result": {"n": n}, "End": True}}}


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListStateMachineVersions returns exactly the published versions, each a distinct
    version ARN, ordered newest-published-first, and that order is stable across repeated
    independent reads."""
    sfn = ctx.client("stepfunctions")
    arn = _create_state_machine(ctx, _pass_def(0))

    published = []
    for n in range(1, 4):
        sfn.update_state_machine(stateMachineArn=arn, definition=json.dumps(_pass_def(n)))
        v = sfn.publish_state_machine_version(stateMachineArn=arn)
        published.append(v["stateMachineVersionArn"])

    listed = sfn.list_state_machine_versions(stateMachineArn=arn)
    listed_arns = [v["stateMachineVersionArn"] for v in listed["stateMachineVersions"]]
    assert set(listed_arns) == set(published), f"{set(listed_arns)} != {set(published)}"
    assert len(listed_arns) == 3, f"expected 3 published versions, got {len(listed_arns)}: {listed_arns}"

    expected_order = list(reversed(published))
    assert listed_arns == expected_order, (
        f"expected newest-published-first order {expected_order}, got {listed_arns}"
    )

    listed_again = sfn.list_state_machine_versions(stateMachineArn=arn)
    listed_arns_again = [v["stateMachineVersionArn"] for v in listed_again["stateMachineVersions"]]
    assert listed_arns_again == listed_arns, (
        f"version order changed between two identical reads: {listed_arns} != {listed_arns_again}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
