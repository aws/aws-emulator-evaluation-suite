"""pass-result-path-doubling-output-over-256kib-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "pass-result-path-doubling-output-over-256kib-rejected"
GROUP = 'pass_state'
SERVICES = ['stepfunctions']

_UNDER_BYTES = 127 * 1024
_OVER_BYTES = 129 * 1024

_SFN_TRUST_POLICY = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Principal": {"Service": "states.amazonaws.com"},
        "Action": "sts:AssumeRole",
    }],
})

_DEFINITION = json.dumps({
    "Comment": "a Pass state whose ResultPath merges a copy of the whole input back into it",
    "StartAt": "Pass",
    "States": {
        "Pass": {
            "Type": "Pass",
            "ResultPath": "$.doubled",
            "End": True,
        }
    },
})


def _create_sfn_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-sfnpass-")
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=_SFN_TRUST_POLICY,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return role_arn


def _create_state_machine(ctx, role_arn: str) -> str:
    """CreateStateMachine as EXPRESS, retrying while the fresh role propagates."""
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-behav-sfnpass-sm-")
    deadline = time.monotonic() + 90.0
    last_err = None
    while time.monotonic() < deadline:
        try:
            arn = sfn.create_state_machine(
                name=name, definition=_DEFINITION, roleArn=role_arn, type="EXPRESS",
                tags=[{"key": "sim2real", "value": CHECK}],
            )["stateMachineArn"]
            ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
            return arn
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException":
                raise
            last_err = exc
            time.sleep(3)
    raise AssertionError(f"CreateStateMachine never stopped denying the fresh role: {last_err!r}")


def _sync_run(ctx, sm_arn: str, payload: dict, *, attempts: int = 6) -> dict:
    """StartSyncExecution, retrying while the fresh role's assume-role grant propagates."""
    sfn = ctx.client("stepfunctions")
    last = None
    for _ in range(attempts):
        last = sfn.start_sync_execution(
            stateMachineArn=sm_arn,
            name=ctx.unique_name("sim2real-behav-exec-"),
            input=json.dumps(payload),
        )
        blob = (last.get("error") or "") + (last.get("cause") or "")
        if last["status"] != "FAILED" or "AccessDenied" not in blob and "not authorized" not in blob:
            return last
        time.sleep(5)
    return last


@tags(
    "axis:rejection",
    "cap:c3",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """A Pass state's ResultPath merges a copy of the whole input back in, roughly doubling
    its size; past 256 KiB that fails States.DataLimitExceeded naming the Pass state, while
    127 KiB doubled stays under the limit and succeeds intact.
    """
    role_arn = _create_sfn_role(ctx)
    sm_arn = _create_state_machine(ctx, role_arn)

    under_input = {"blob": "x" * _UNDER_BYTES}
    ok = _sync_run(ctx, sm_arn, under_input)
    assert ok["status"] == "SUCCEEDED", (
        f"positive control: a {_UNDER_BYTES}-byte input doubled by ResultPath ended "
        f"{ok['status']!r}: {ok.get('error')!r} {ok.get('cause')!r}"
    )
    ok_output = json.loads(ok["output"])
    assert ok_output == {"blob": "x" * _UNDER_BYTES, "doubled": under_input}, (
        f"positive control: the doubled output did not merge intact (output keys "
        f"{sorted(ok_output)!r})"
    )

    over_input = {"blob": "x" * _OVER_BYTES}
    bad = _sync_run(ctx, sm_arn, over_input)
    assert bad["status"] == "FAILED", (
        f"a {_OVER_BYTES}-byte input doubled by ResultPath ended {bad['status']!r}, "
        f"expected FAILED"
    )
    assert bad.get("error") == "States.DataLimitExceeded", (
        f"the oversize doubled output failed with {bad.get('error')!r} ({bad.get('cause')!r}), "
        f"expected States.DataLimitExceeded"
    )
    expected_cause = (
        "The state/task 'Pass' returned a result with a size exceeding the maximum "
        "number of bytes service limit."
    )
    assert bad.get("cause") == expected_cause, (
        f"expected cause {expected_cause!r}, got {bad.get('cause')!r}"
    )
    assert bad.get("output") is None, f"the refused execution produced output: {bad.get('output')!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
