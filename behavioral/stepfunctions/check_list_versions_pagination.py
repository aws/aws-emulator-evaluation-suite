"""list-versions-pagination."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-versions-pagination"
GROUP = 'update_versioning'
SERVICES = ['stepfunctions']


def _create_sfn_role(ctx):
    """Create an execution role Step Functions may assume, deleted at cleanup."""
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
    return arn


def _call_once_role_assumable(create, **kwargs):
    """Call ``create``, retrying while a just-created role is not yet assumable."""
    deadline = time.monotonic() + 60.0
    while True:
        try:
            return create(**kwargs)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException" or time.monotonic() > deadline:
                raise
            time.sleep(3)


def _create_state_machine(ctx, definition, *, name=None, sm_type="STANDARD"):
    sfn = ctx.client("stepfunctions")
    name = name or ctx.unique_name("sim2real-behav-sm-")
    arn = _call_once_role_assumable(
        sfn.create_state_machine,
        name=name,
        definition=json.dumps(definition),
        roleArn=_create_sfn_role(ctx),
        type=sm_type,
        tags=[{"key": "sim2real", "value": "1"}],
    )["stateMachineArn"]
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
    return arn


def _pass_def(n):
    return {"StartAt": "P", "States": {"P": {"Type": "Pass", "Result": {"n": n}, "End": True}}}


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListStateMachineVersions paginates via nextToken without duplicating or dropping entries."""
    sfn = ctx.client("stepfunctions")
    arn = _create_state_machine(ctx, _pass_def(0))

    version_arns = set()
    for n in range(1, 4):
        sfn.update_state_machine(stateMachineArn=arn, definition=json.dumps(_pass_def(n)))
        v = sfn.publish_state_machine_version(stateMachineArn=arn)
        version_arns.add(v["stateMachineVersionArn"])

    seen: list[str] = []
    next_token = None
    pages = 0
    while True:
        kwargs: dict = {"stateMachineArn": arn, "maxResults": 1}
        if next_token:
            kwargs["nextToken"] = next_token
        resp = sfn.list_state_machine_versions(**kwargs)
        pages += 1
        seen.extend(v["stateMachineVersionArn"] for v in resp["stateMachineVersions"])
        next_token = resp.get("nextToken")
        if not next_token or pages > 500:
            break

    assert len(seen) == len(set(seen)), "pagination must not return duplicate versions"
    assert set(seen) == version_arns, f"pagination mismatch: {set(seen)} != {version_arns}"
    assert pages >= 3, f"expected at least 3 pages with maxResults=1 and 3 versions, got {pages}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
