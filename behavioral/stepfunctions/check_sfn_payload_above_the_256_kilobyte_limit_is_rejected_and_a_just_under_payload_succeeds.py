"""sfn-payload-above-the-256-kilobyte-limit-is-rejected-and-a-just-under-payload-succeeds."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sfn-payload-above-the-256-kilobyte-limit-is-rejected-and-a-just-under-payload-succeeds"
GROUP = 'quota'
SERVICES = ['stepfunctions']

_LIMIT = 256 * 1024
_N_ITEMS = 64


@tags(
    "axis:rejection",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
    "cap:c3",
)
def run(ctx) -> None:
    """StartExecution above the 256 KiB payload limit is rejected and creates no execution,
    while a payload just under it runs and the interpreter reports what it received.
    """
    sfn = ctx.client("stepfunctions")

    _role_name, role_arn = _create_sfn_role(
        ctx, [{"Effect": "Allow", "Action": "states:DescribeExecution", "Resource": "*"}]
    )
    definition = {
        "Comment": "report back a value the interpreter computed from the payload it received",
        "StartAt": "Count",
        "States": {
            "Count": {
                "Type": "Pass",
                "Parameters": {"count.$": "States.ArrayLength($.items)"},
                "End": True,
            }
        },
    }
    sm_arn = _create_state_machine(ctx, definition, role_arn)

    too_big = _payload(_LIMIT + 1024)
    ok_input = _payload(_LIMIT - 2048)
    assert len(too_big.encode()) == _LIMIT + 1024 and len(ok_input.encode()) == _LIMIT - 2048, (
        f"the payload builder is wrong: {len(too_big.encode())!r} and "
        f"{len(ok_input.encode())!r} bytes"
    )

    before = _execution_arns(ctx, sm_arn)

    code, status, message = _error_code_and_message(lambda: sfn.start_execution(
        stateMachineArn=sm_arn,
        name=ctx.unique_name("sim2real-behav-exec-toobig-"),
        input=too_big,
    ))
    assert (code, status) == ("ValidationException", 400), (
        f"expected ValidationException/400 for a {len(too_big.encode())!r}-byte input, got "
        f"{code!r}/{status!r}: {message[:200]!r}"
    )
    expected_message = "1 validation error detected: Value at 'input' failed to satisfy constraint: Member must have size less than or equal to 262144 bytes in UTF-8 encoding"
    assert message == expected_message, f"expected the message {expected_message!r}, got {message!r}"

    after = _execution_arns(ctx, sm_arn)
    assert after == before, (
        f"an execution appeared for a rejected input: {sorted(after - before)!r}"
    )

    exe = _run_to_terminal(ctx, sm_arn, ok_input)
    assert exe["status"] == "SUCCEEDED", (
        f'the {len(ok_input.encode())!r}-byte input execution was {exe["status"]!r}: '
        f'{exe.get("error")!r} {exe.get("cause")!r}'
    )
    assert json.loads(exe["output"])["count"] == _N_ITEMS, (
        f'the interpreter computed count={json.loads(exe["output"]).get("count")!r} over the '
        f"payload it received, expected {_N_ITEMS!r}"
    )
    assert len(exe["input"].encode()) == len(ok_input.encode()), (
        f'the recorded input is {len(exe["input"].encode())!r} bytes, '
        f"{len(ok_input.encode())!r} were sent"
    )

    # And the accepted execution IS in the list, so the absence asserted above is a real
    # absence rather than a listing that never shows anything.
    assert exe["executionArn"] in _execution_arns(ctx, sm_arn), (
        f'the accepted execution {exe["executionArn"]!r} is missing from ListExecutions, so '
        f"the absence assertion over the rejected input proves nothing"
    )


def _payload(total_bytes: int) -> str:
    """A JSON object of exactly ``total_bytes`` bytes holding an array of _N_ITEMS strings."""
    body = {"items": [f"sim2real-item-{i:05d}" for i in range(_N_ITEMS)], "pad": ""}
    filler = total_bytes - len(json.dumps(body, separators=(",", ":")).encode())
    assert filler >= 0, f"{total_bytes!r} bytes is too small for the {_N_ITEMS!r}-element array"
    body["pad"] = "x" * filler
    return json.dumps(body, separators=(",", ":"))


def _error_code_and_message(fn):
    try:
        fn()
    except ClientError as exc:
        status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
        return exc.response["Error"]["Code"], status, exc.response["Error"].get("Message") or ""
    raise AssertionError(
        "StartExecution unexpectedly SUCCEEDED on an over-limit payload; real AWS rejects it"
    )


def _execution_arns(ctx, sm_arn):
    """Every execution of this state machine, paginated."""
    sfn = ctx.client("stepfunctions")
    arns, token = set(), None
    while True:
        kwargs = {"stateMachineArn": sm_arn, "maxResults": 100}
        if token:
            kwargs["nextToken"] = token
        resp = sfn.list_executions(**kwargs)
        arns.update(e["executionArn"] for e in resp["executions"])
        token = resp.get("nextToken")
        if not token:
            return arns


def _create_sfn_role(ctx, statements):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-sfnrole-")
    trust = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "states.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    })
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=trust,
        Description="sim2real-behav sfn execution role",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    policy_name = f"{role_name}-policy"

    def _delete_role():
        for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            try:
                iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_delete_role)
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
    )
    # IAM propagation exposes no condition to poll; the bounded AccessDeniedException retry in
    # _create_state_machine covers it.
    return role_name, role_arn


def _create_state_machine(ctx, definition, role_arn, *, sm_type="STANDARD",
                          name_prefix="sim2real-behav-sm-"):
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name(name_prefix)
    deadline = time.monotonic() + 90.0
    last = None
    while time.monotonic() < deadline:
        try:
            arn = sfn.create_state_machine(
                name=name, definition=json.dumps(definition), roleArn=role_arn, type=sm_type,
                tags=[{"key": "sim2real", "value": CHECK}],
            )["stateMachineArn"]
            ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
            return arn
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException":
                raise
            last = exc
            time.sleep(3)
    raise AssertionError(f"CreateStateMachine never stopped denying the role: {last!r}")


def _run_to_terminal(ctx, sm_arn, input_str, *, timeout_s=120.0):
    sfn = ctx.client("stepfunctions")
    exec_arn = sfn.start_execution(
        stateMachineArn=sm_arn,
        name=ctx.unique_name("sim2real-behav-exec-"),
        input=input_str,
    )["executionArn"]
    ctx.on_cleanup(lambda: _best_effort_stop(ctx, exec_arn))
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = sfn.describe_execution(executionArn=exec_arn)
        if last["status"] in ("SUCCEEDED", "FAILED", "TIMED_OUT", "ABORTED"):
            return last
        time.sleep(1.5)
    raise AssertionError(f"execution {exec_arn} was not terminal within {timeout_s}s: {last!r}")


def _best_effort_stop(ctx, exec_arn):
    sfn = ctx.client("stepfunctions")
    try:
        sfn.stop_execution(executionArn=exec_arn, error="cleanup", cause="sim2real cleanup")
    except ClientError as exc:
        # StopExecution is a no-op on a terminal execution; only a vanished one is not an error.
        if exc.response["Error"]["Code"] != "ExecutionDoesNotExist":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
