"""start-execution-input-exactly-256kib-succeeds."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "start-execution-input-exactly-256kib-succeeds"
GROUP = 'quota'
SERVICES = ['stepfunctions']

_LIMIT = 256 * 1024
_N_ITEMS = 64


@tags(
    "axis:happy-path",
    "concern:data-plane",
    "dp:api",
    "plane:data",
    "cap:c3",
)
def run(ctx) -> None:
    """A StartSyncExecution input of exactly the 262144-byte limit starts and the interpreter
    reports a value it computed over the payload it received, byte for byte.
    """
    sfn = ctx.client("stepfunctions")
    role_arn = _create_sfn_role(ctx)
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

    exact_input = _payload(_LIMIT)
    assert len(exact_input.encode()) == _LIMIT, (
        f"the payload builder is wrong: {len(exact_input.encode())!r} bytes, expected {_LIMIT!r}"
    )

    result = sfn.start_sync_execution(
        stateMachineArn=sm_arn,
        name=ctx.unique_name("sim2real-behav-exec-exact-"),
        input=exact_input,
    )
    assert result["status"] == "SUCCEEDED", (
        f"an exactly {_LIMIT!r}-byte input ended {result['status']!r}: "
        f"{result.get('error')!r} {result.get('cause')!r}"
    )
    assert json.loads(result["output"])["count"] == _N_ITEMS, (
        f'the interpreter computed count={json.loads(result["output"]).get("count")!r} over the '
        f"payload it received, expected {_N_ITEMS!r}"
    )
    assert len(result["input"].encode()) == _LIMIT, (
        f'the recorded input is {len(result["input"].encode())!r} bytes, expected exactly {_LIMIT!r}'
    )


def _payload(total_bytes: int) -> str:
    """A JSON object of exactly ``total_bytes`` bytes holding an array of _N_ITEMS strings."""
    body = {"items": [f"sim2real-item-{i:05d}" for i in range(_N_ITEMS)], "pad": ""}
    filler = total_bytes - len(json.dumps(body, separators=(",", ":")).encode())
    assert filler >= 0, f"{total_bytes!r} bytes is too small for the {_N_ITEMS!r}-element array"
    body["pad"] = "x" * filler
    return json.dumps(body, separators=(",", ":"))


def _create_sfn_role(ctx):
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
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=role_name), "NoSuchEntity"))
    # IAM propagation exposes no condition to poll; the bounded AccessDeniedException retry in
    # _create_state_machine covers it.
    return role_arn


def _create_state_machine(ctx, definition, role_arn):
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-behav-sm-")
    deadline = time.monotonic() + 90.0
    last = None
    while time.monotonic() < deadline:
        try:
            arn = sfn.create_state_machine(
                name=name, definition=json.dumps(definition), roleArn=role_arn, type="EXPRESS",
                tags=[{"key": "sim2real", "value": CHECK}],
            )["stateMachineArn"]
            ctx.on_cleanup(_teardown(
                lambda: sfn.delete_state_machine(stateMachineArn=arn), "StateMachineDoesNotExist"
            ))
            return arn
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException":
                raise
            last = exc
            time.sleep(3)
    raise AssertionError(f"CreateStateMachine never stopped denying the role: {last!r}")


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
