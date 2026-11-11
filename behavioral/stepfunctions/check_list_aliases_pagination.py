"""list-aliases-pagination."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-aliases-pagination"
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
    )["stateMachineArn"]
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
    return arn


def _asl_pass(result=None):
    state = {"Type": "Pass", "End": True}
    if result is not None:
        state["Result"] = result
    return {"Comment": "behavioral-pass", "StartAt": "P", "States": {"P": state}}


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListStateMachineAliases paginates without duplicating or dropping entries."""
    sfn = ctx.client("stepfunctions")
    arn = _create_state_machine(ctx, _asl_pass())
    v1_arn = sfn.publish_state_machine_version(stateMachineArn=arn)["stateMachineVersionArn"]

    alias_arns = set()
    for i in range(3):
        alias_name = ctx.unique_name(f"sim2real-behav-alias-page-{i}-")
        sfn.create_state_machine_alias(
            name=alias_name, routingConfiguration=[{"stateMachineVersionArn": v1_arn, "weight": 100}]
        )
        alias_arns.add(f"{arn}:{alias_name}")

    seen: list[str] = []
    next_token = None
    pages = 0
    while True:
        kwargs: dict = {"stateMachineArn": arn, "maxResults": 1}
        if next_token:
            kwargs["nextToken"] = next_token
        resp = sfn.list_state_machine_aliases(**kwargs)
        pages += 1
        seen.extend(a["stateMachineAliasArn"] for a in resp["stateMachineAliases"])
        next_token = resp.get("nextToken")
        if not next_token or pages > 500:
            break

    assert len(seen) == len(set(seen)), "pagination must not return duplicate aliases"
    assert set(seen) == alias_arns, f"pagination mismatch: {set(seen)} != {alias_arns}"
    assert pages >= 3, f"expected at least 3 pages with maxResults=1 and 3 aliases, got {pages}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
