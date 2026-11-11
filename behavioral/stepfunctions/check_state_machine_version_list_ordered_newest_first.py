"""state-machine-version-list-ordered-newest-first."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "state-machine-version-list-ordered-newest-first"
GROUP = "ordering"
SERVICES = ["stepfunctions"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListStateMachineVersions returns published versions newest-to-oldest, and that
    order is stable across repeated calls and across pagination."""
    sfn = ctx.client("stepfunctions")
    role_arn = _create_sfn_role(ctx)
    name = ctx.unique_name("sim2real-behav-verord-")

    def _def(tag):
        return json.dumps({"Comment": tag, "StartAt": "Done", "States": {"Done": {"Type": "Succeed"}}})

    sm_arn = _create_state_machine(ctx, sfn, name, _def("v0"), role_arn)
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=sm_arn))

    version_arns = []
    for i in range(1, 4):
        sfn.update_state_machine(stateMachineArn=sm_arn, definition=_def(f"v{i}"))
        pub = sfn.publish_state_machine_version(stateMachineArn=sm_arn)
        version_arns.append(pub["stateMachineVersionArn"])

    for v in version_arns:
        ctx.on_cleanup(lambda v=v: sfn.delete_state_machine_version(stateMachineVersionArn=v))

    def _list_all_versions(**extra):
        items = []
        token = None
        while True:
            kwargs = {"stateMachineArn": sm_arn, **extra}
            if token:
                kwargs["nextToken"] = token
            resp = sfn.list_state_machine_versions(**kwargs)
            items.extend(resp["stateMachineVersions"])
            token = resp.get("nextToken")
            if not token:
                break
        return items

    listed1 = _list_all_versions()
    listed_arns1 = [v["stateMachineVersionArn"] for v in listed1]
    expected_order = list(reversed(version_arns))
    assert listed_arns1 == expected_order, f"expected newest-first {expected_order}, got {listed_arns1}"

    listed2 = _list_all_versions()
    listed_arns2 = [v["stateMachineVersionArn"] for v in listed2]
    assert listed_arns2 == listed_arns1, "version order changed between two identical calls"

    paged = _list_all_versions(maxResults=1)
    paged_arns = [v["stateMachineVersionArn"] for v in paged]
    assert paged_arns == listed_arns1, "paginated version order does not match unpaginated order"


def _create_sfn_role(ctx, extra_statements=None):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-sfnrole-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "states.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    statements = list(extra_statements or [])
    if not statements:
        statements = [{"Effect": "Allow", "Action": "states:DescribeExecution", "Resource": "*"}]
    policy_name = f"{role_name}-policy"
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))

    return iam.get_role(RoleName=role_name)["Role"]["Arn"]


def _create_state_machine(ctx, sfn, name, definition, role_arn, type_="STANDARD"):
    deadline = time.monotonic() + 60.0
    last_err = None
    while time.monotonic() < deadline:
        try:
            resp = sfn.create_state_machine(
                name=name,
                definition=definition,
                roleArn=role_arn,
                type=type_,
                tags=[{"key": "sim2real", "value": "true"}],
            )
            return resp["stateMachineArn"]
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "AccessDeniedException":
                last_err = exc
                time.sleep(3)
                continue
            raise
    raise AssertionError(f"could not create state machine after IAM propagation wait: {last_err}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
