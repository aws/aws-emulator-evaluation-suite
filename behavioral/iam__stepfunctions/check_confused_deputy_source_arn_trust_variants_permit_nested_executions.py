"""confused-deputy-source-arn-trust-variants-permit-nested-executions."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "confused-deputy-source-arn-trust-variants-permit-nested-executions"
GROUP = "confused_deputy"
SERVICES = ["iam", "stepfunctions"]

_NON_ASCII = "з"  # Cyrillic 'з', a single code point an IAM StringLike "?" must match.

_CHILD_DEFINITION = json.dumps({
    "StartAt": "Compute",
    "States": {
        "Compute": {
            "Type": "Pass",
            "Parameters": {"value.$": "States.Format('{}-child', $.seed)"},
            "End": True,
        },
    },
})


def _parent_definition(child_arn: str) -> str:
    return json.dumps({
        "StartAt": "CallChild",
        "States": {
            "CallChild": {
                "Type": "Task",
                "Resource": "arn:aws:states:::states:startExecution.sync:2",
                "Parameters": {"StateMachineArn": child_arn, "Input": {"seed.$": "$.seed"}},
                "ResultSelector": {"fromChild.$": "$.Output.value"},
                "End": True,
            },
        },
    })


def _trust(condition: dict) -> str:
    return json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "states.amazonaws.com"},
            "Action": "sts:AssumeRole",
            "Condition": condition,
        }],
    })


def _create_role(ctx, trust_doc: str, statements: list[dict]) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-xsvc-cd-")[:64]
    arn = iam.create_role(
        RoleName=name, AssumeRolePolicyDocument=trust_doc, Path="/sim2real/",
        Description="sim2real-xsvc: sfn confused-deputy trust role",
        Tags=[{"Key": "sim2real", "Value": CHECK[:250]}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    iam.put_role_policy(
        RoleName=name, PolicyName="perms",
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=name, PolicyName="perms"))
    return arn


def _create_named_state_machine(ctx, name: str, definition: str, role_arn: str,
                                *, deadline_s: float = 120.0) -> str:
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + deadline_s
    last = None
    while time.monotonic() < deadline:
        try:
            arn = sfn.create_state_machine(
                name=name, definition=definition, roleArn=role_arn, type="STANDARD",
                tags=[{"key": "sim2real", "value": CHECK[:250]}],
            )["stateMachineArn"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException":
                raise
            last = exc
            time.sleep(4.0)
            continue
        ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
        return arn
    raise AssertionError(f"CreateStateMachine {name!r} still AccessDenied after {deadline_s}s: {last}")


_TRUST_RACE_MARKERS = (
    "not authorized to assume",
    "cannot be assumed",
    "AccessDeniedException",
)


def _run_to_terminal(ctx, sm_arn: str, seed: str, *, deadline_s: float = 150.0) -> dict:
    """StartExecution, retrying only while the role's (freshly-created) trust has not propagated."""
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + deadline_s
    desc = None
    while time.monotonic() < deadline:
        exec_arn = sfn.start_execution(
            stateMachineArn=sm_arn, name=ctx.unique_name("sim2real-xsvc-cd-exec-"),
            input=json.dumps({"seed": seed}),
        )["executionArn"]
        ctx.on_cleanup(lambda a=exec_arn: _best_effort_stop(ctx, a))
        desc = _wait_terminal(ctx, exec_arn, timeout_s=90.0)
        blob = (desc.get("cause") or "") + (desc.get("error") or "")
        if desc["status"] != "FAILED" or not any(m in blob for m in _TRUST_RACE_MARKERS):
            return desc
        time.sleep(4.0)
    raise AssertionError(f"execution of {sm_arn!r} never got past trust propagation: {desc!r}")


def _wait_terminal(ctx, exec_arn: str, *, timeout_s: float = 90.0) -> dict:
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = sfn.describe_execution(executionArn=exec_arn)
        if last["status"] != "RUNNING":
            return last
        time.sleep(2.0)
    raise AssertionError(f"execution {exec_arn} still RUNNING after {timeout_s}s: {last!r}")


def _best_effort_stop(ctx, exec_arn: str) -> None:
    sfn = ctx.client("stepfunctions")
    try:
        if sfn.describe_execution(executionArn=exec_arn)["status"] == "RUNNING":
            sfn.stop_execution(executionArn=exec_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ExecutionDoesNotExist":
            raise


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """An execution role whose trust requires aws:SourceArn equal to the calling state
    machine's own ARN -- exact, wildcard, or a non-ASCII character matched by "?" -- is
    assumable, and a nested .sync:2 execution it starts runs to completion.
    """
    sfn = ctx.client("stepfunctions")
    child_role_arn = _create_role(ctx, _trust({}), [
        {"Effect": "Allow", "Action": "states:DescribeExecution", "Resource": "*"}])
    child_arn = _create_named_state_machine(
        ctx, ctx.unique_name("sim2real-xsvc-cdchild-"), _CHILD_DEFINITION, child_role_arn)

    region, account = ctx.region, ctx.account

    def _parent_perms(parent_arn: str) -> list[dict]:
        return [
            {"Effect": "Allow", "Action": "states:StartExecution", "Resource": child_arn},
            {"Effect": "Allow", "Action": ["states:DescribeExecution", "states:StopExecution"],
             "Resource": f"arn:aws:states:{region}:{account}:execution:*:*"},
            {"Effect": "Allow",
             "Action": ["events:PutTargets", "events:PutRule", "events:DescribeRule"],
             "Resource": (f"arn:aws:events:{region}:{account}:rule/"
                          "StepFunctionsGetEventsForStepFunctionsExecutionRule")},
        ]

    # (1) exact match.
    exact_name = ctx.unique_name("sim2real-xsvc-cdexact-")
    exact_arn = f"arn:aws:states:{region}:{account}:stateMachine:{exact_name}"
    exact_role = _create_role(
        ctx, _trust({"StringEquals": {"aws:SourceArn": exact_arn}}), _parent_perms(exact_arn))
    exact_sm = _create_named_state_machine(
        ctx, exact_name, _parent_definition(child_arn), exact_role)
    assert exact_sm == exact_arn, f"created ARN {exact_sm!r} != predicted {exact_arn!r}"

    # (2) wildcard over names.
    wild_name = ctx.unique_name("sim2real-xsvc-cdwild-")
    wild_arn = f"arn:aws:states:{region}:{account}:stateMachine:{wild_name}"
    wild_pattern = f"arn:aws:states:{region}:{account}:stateMachine:sim2real-xsvc-cdwild-*"
    wild_role = _create_role(
        ctx, _trust({"StringLike": {"aws:SourceArn": wild_pattern}}), _parent_perms(wild_arn))
    wild_sm = _create_named_state_machine(
        ctx, wild_name, _parent_definition(child_arn), wild_role)
    assert wild_sm == wild_arn, f"created ARN {wild_sm!r} != predicted {wild_arn!r}"

    # (3) a non-ASCII name character matched by a single-character "?" wildcard.
    suffix = ctx.unique_name("")
    nonascii_name = f"sim2real-xsvc-cd{_NON_ASCII}-{suffix}"
    nonascii_pattern = f"arn:aws:states:{region}:{account}:stateMachine:sim2real-xsvc-cd?-{suffix}"
    nonascii_arn = f"arn:aws:states:{region}:{account}:stateMachine:{nonascii_name}"
    nonascii_role = _create_role(
        ctx, _trust({"StringLike": {"aws:SourceArn": nonascii_pattern}}),
        _parent_perms(nonascii_arn))
    nonascii_sm = _create_named_state_machine(
        ctx, nonascii_name, _parent_definition(child_arn), nonascii_role)
    assert nonascii_sm == nonascii_arn, f"created ARN {nonascii_sm!r} != predicted {nonascii_arn!r}"

    for label, sm_arn in (("exact", exact_sm), ("wildcard-over-names", wild_sm),
                          ("non-ascii-?", nonascii_sm)):
        seed = ctx.unique_name(f"sim2real-seed-{label}-")
        parent = _run_to_terminal(ctx, sm_arn, seed)
        assert parent["status"] == "SUCCEEDED", (
            f"[{label}] a SourceArn-conditioned trust matching the calling state machine must "
            f"let it assume its role and SUCCEED; got {parent['status']!r} "
            f"error={parent.get('error')!r} cause={parent.get('cause')!r}")
        out = json.loads(parent["output"])
        assert out == {"fromChild": f"{seed}-child"}, (
            f"[{label}] the nested .sync:2 child's output must reach the parent; got {out!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
