"""list-executions-status-filter-ordering."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-executions-status-filter-ordering"
GROUP = "ordering"
SERVICES = ["stepfunctions"]


@tags("axis:happy-path", "cap:c2", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """ListExecutions with a status filter returns executions most-recent-first, and
    that order is stable across repeated calls and across pagination."""
    sfn = ctx.client("stepfunctions")
    role_arn = _create_sfn_role(ctx)
    name = ctx.unique_name("sim2real-behav-listexec-")
    definition = json.dumps({"StartAt": "Done", "States": {"Done": {"Type": "Succeed"}}})
    sm_arn = _create_state_machine(ctx, sfn, name, definition, role_arn)
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=sm_arn))

    exec_arns = []
    for i in range(4):
        resp = sfn.start_execution(stateMachineArn=sm_arn, name=ctx.unique_name(f"exec{i}-"))
        exec_arns.append(resp["executionArn"])
        time.sleep(1.2)  # keep startDate values distinguishable

    for arn in exec_arns:
        _poll_until(
            lambda a=arn: sfn.describe_execution(executionArn=a)["status"],
            lambda status: status == "SUCCEEDED",
            timeout_s=30.0,
            interval_s=1.0,
        )

    def _list_all(**kwargs):
        items = []
        token = None
        while True:
            call_kwargs = dict(kwargs)
            if token:
                call_kwargs["nextToken"] = token
            resp = sfn.list_executions(**call_kwargs)
            items.extend(resp["executions"])
            token = resp.get("nextToken")
            if not token:
                break
        return items

    full1 = _poll_until(
        lambda: _list_all(stateMachineArn=sm_arn, statusFilter="SUCCEEDED"),
        lambda lst: len(lst) >= len(exec_arns),
        timeout_s=30.0,
        interval_s=1.5,
    )
    order1 = [e["executionArn"] for e in full1]
    expected_order = list(reversed(exec_arns))
    assert order1 == expected_order, f"expected most-recent-first order {expected_order}, got {order1}"

    full2 = _list_all(stateMachineArn=sm_arn, statusFilter="SUCCEEDED")
    order2 = [e["executionArn"] for e in full2]
    assert order2 == order1, "ListExecutions order changed between two identical calls"

    paged = _list_all(stateMachineArn=sm_arn, statusFilter="SUCCEEDED", maxResults=1)
    paged_order = [e["executionArn"] for e in paged]
    assert paged_order == order1, "paginated order does not match the unpaginated order"


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


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
        Tags=[{"Key": "sim2real", "Value": CHECK}],
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
                tags=[{"key": "sim2real", "value": name}],
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
