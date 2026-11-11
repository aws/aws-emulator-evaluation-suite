"""events-putevents-task-without-permission-is-caught-as-access-denied."""

from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "events-putevents-task-without-permission-is-caught-as-access-denied"
GROUP = "task_integrations"
SERVICES = ["events", "stepfunctions"]

#: The ASL error name an events:putEvents task reports when EventBridge refuses the call.
_ERROR_NAME = "EventBridge.AmazonEventBridgeException"

#: The caught Cause for the denied role; ``{partition}``, ``{account}``, ``{role}`` and ``{bus}``
#: are filled in.
_DENIED_CAUSE = (
    "User: arn:{partition}:sts::{account}:assumed-role/{role}/<session> is not authorized to "
    "perform: events:PutEvents on resource: {bus} because no identity-based policy allows the "
    "events:PutEvents action (Service: AmazonEventBridge; Status Code: 400; Error Code: "
    "AccessDeniedException; Request ID: <id>; Proxy: null)"
)

_DETAIL_TYPE = "sim2real.putevents.denied"


@tags(
    "axis:rejection",
    "cap:c1",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """An events:putEvents task without events:PutEvents fails catchably.

    EventBridge's AccessDeniedException is caught by a Catch on the task's error name; a sibling
    role holding events:PutEvents on the default bus runs the same task to success.
    """
    denied_role_name, denied_role = _create_sfn_role(ctx, statements=[])
    partition = denied_role.split(":")[1]
    bus_arn = f"arn:{partition}:events:{ctx.region}:{ctx.account}:event-bus/default"
    _, allowed_role = _create_sfn_role(
        ctx,
        statements=[
            {"Effect": "Allow", "Action": "events:PutEvents", "Resource": bus_arn},
        ],
    )
    denied_sm = _create_state_machine(ctx, denied_role)
    allowed_sm = _create_state_machine(ctx, allowed_role)

    desc = _run_to_terminal(ctx, denied_sm, retry_if=_caught_propagation)
    assert desc["status"] == "SUCCEEDED", (
        f"the Catch on {_ERROR_NAME!r} must handle the denial and end SUCCEEDED, got "
        f"{desc['status']!r}: error={desc.get('error')!r} cause={desc.get('cause')!r}"
    )
    out = json.loads(desc["output"])
    assert out.get("handled") == "denied", f"the Denied state did not run: {out!r}"
    err = out.get("err") or {}
    assert err.get("Error") == _ERROR_NAME, f"the caught error name was {err.get('Error')!r}"
    masked = _mask(err.get("Cause"), denied_role_name)
    expected = _DENIED_CAUSE.format(
        partition=partition, account=ctx.account, role=denied_role_name, bus=bus_arn
    )
    assert masked == expected, f"the caught cause was {err.get('Cause')!r}, expected {expected!r}"

    # Positive control: the identical task with the permission granted succeeds directly; a
    # caught denial there is the fresh grant still propagating, so it is retried.
    ok = _run_to_terminal(ctx, allowed_sm, retry_if=_caught_denial)
    assert ok["status"] == "SUCCEEDED", (
        f"the allowed sibling ended {ok['status']!r}: {ok.get('error')!r} {ok.get('cause')!r}"
    )
    ok_out = json.loads(ok["output"])
    assert "handled" not in ok_out and ok_out.get("FailedEntryCount") == 0, (
        f"the allowed sibling must put its event without failure, got {ok_out!r}"
    )


# ===== helpers =====


def _budget_s(ctx, cap_s):
    """A wait's timeout: cap_s, capped by the runner's remaining time less 5 s."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _mask(cause, role_name):
    masked = re.sub(r"Request ID: [0-9a-zA-Z-]+;", "Request ID: <id>;", cause or "")
    return re.sub(
        rf"/{re.escape(role_name)}/[^ ]+ is not", f"/{role_name}/<session> is not", masked
    )


def _create_sfn_role(ctx, statements):
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-role-")
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=name), "NoSuchEntity"))
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(
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
        ),
        Tags=[{"Key": "sim2real", "Value": CHECK[:200]}],
    )["Role"]["Arn"]
    if statements:
        ctx.on_cleanup(
            _teardown(
                lambda: iam.delete_role_policy(RoleName=name, PolicyName="inline"), "NoSuchEntity"
            )
        )
        iam.put_role_policy(
            RoleName=name,
            PolicyName="inline",
            PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
        )
    return name, arn


def _create_state_machine(ctx, role_arn):
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-behav-sm-")
    partition = role_arn.split(":")[1]
    definition = {
        "Comment": "sim2real: one events:putEvents task with a Catch on its error name",
        "StartAt": "Put",
        "States": {
            "Put": {
                "Type": "Task",
                "Resource": f"arn:{partition}:states:::events:putEvents",
                "Parameters": {
                    "Entries": [
                        {
                            "Source": "sim2real.check",
                            "DetailType": _DETAIL_TYPE,
                            "Detail": {"marker": "ok"},
                        }
                    ]
                },
                "Catch": [{"ErrorEquals": [_ERROR_NAME], "ResultPath": "$.err", "Next": "Denied"}],
                "End": True,
            },
            "Denied": {
                "Type": "Pass",
                "Parameters": {"handled": "denied", "err.$": "$.err"},
                "End": True,
            },
        },
    }
    arn = f"arn:{partition}:states:{ctx.region}:{ctx.account}:stateMachine:{name}"
    ctx.on_cleanup(
        _teardown(lambda: sfn.delete_state_machine(stateMachineArn=arn), "StateMachineDoesNotExist")
    )
    deadline = time.monotonic() + _budget_s(ctx, 90.0)
    last = None
    while time.monotonic() < deadline:
        try:
            return sfn.create_state_machine(
                name=name,
                definition=json.dumps(definition),
                roleArn=role_arn,
                type="STANDARD",
                tags=[{"key": "sim2real", "value": CHECK[:200]}],
            )["stateMachineArn"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException":
                raise
            last = exc
            time.sleep(3)
    raise AssertionError(f"CreateStateMachine never stopped denying the fresh role: {last!r}")


_TRUST_PROPAGATION_MARKERS = (
    "not authorized to assume",
    "cannot be assumed",
    "UnrecognizedClientException",
    "InvalidClientTokenId",
    "security token included in the request is invalid",
)


def _best_effort_stop(ctx, exec_arn):
    try:
        ctx.client("stepfunctions").stop_execution(
            executionArn=exec_arn, error="sim2real-cleanup", cause="cleanup"
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ExecutionDoesNotExist":
            raise


def _wait_terminal(ctx, exec_arn, *, cap_s=60.0, interval_s=1.0):
    sfn = ctx.client("stepfunctions")
    timeout_s = _budget_s(ctx, cap_s)
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = sfn.describe_execution(executionArn=exec_arn)
        if last["status"] in ("SUCCEEDED", "FAILED", "TIMED_OUT", "ABORTED"):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"execution {exec_arn} was not terminal within {timeout_s}s: {last!r}")


def _caught_denial(desc) -> bool:
    """A SUCCEEDED execution whose Catch handled the denial."""
    return desc["status"] == "SUCCEEDED" and "handled" in json.loads(desc.get("output") or "{}")


def _caught_propagation(desc) -> bool:
    """A SUCCEEDED execution whose Catch handled a not-yet-usable role, not the denial."""
    if not _caught_denial(desc):
        return False
    cause = (json.loads(desc["output"]).get("err") or {}).get("Cause") or ""
    return any(m in cause for m in _TRUST_PROPAGATION_MARKERS)


def _run_to_terminal(ctx, sm_arn, *, retry_if=None, propagation_s=90.0):
    """Retry while the fresh role's trust, or a grant retry_if detects, is still propagating.

    A denial from the missing permission never names role assumption, so by default it is
    never retried.
    """
    sfn = ctx.client("stepfunctions")
    retry_until = time.monotonic() + _budget_s(ctx, propagation_s)
    while True:
        exec_name = ctx.unique_name("sim2real-behav-exec-")
        exec_arn = sm_arn.replace(":stateMachine:", ":execution:", 1) + ":" + exec_name
        ctx.on_cleanup(lambda a=exec_arn: _best_effort_stop(ctx, a))
        sfn.start_execution(
            stateMachineArn=sm_arn,
            name=exec_name,
            input="{}",
        )
        desc = _wait_terminal(ctx, exec_arn)
        blob = (desc.get("cause") or "") + (desc.get("error") or "")
        propagating = desc["status"] == "FAILED" and any(
            m in blob for m in _TRUST_PROPAGATION_MARKERS
        )
        if not propagating and not (retry_if and retry_if(desc)):
            return desc
        if time.monotonic() >= retry_until:
            return desc
        time.sleep(3)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
