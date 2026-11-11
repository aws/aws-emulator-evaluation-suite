"""sfn-reassigning-or-leaving-map-scope-frees-variable-space."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sfn-reassigning-or-leaving-map-scope-frees-variable-space"
GROUP = "variables"
SERVICES = ["stepfunctions"]

_TRUST = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"Service": "states.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }
    ],
}

# Each state below assigns a variable at exactly the per-variable cap (262142 content characters,
# 262144 bytes once JSON-quoted); 60 of them is 15,728,640 bytes, well past the 10 MiB
# execution-total cap if the bytes were to accumulate.
_VALUE = "{% $pad('', 262142, 'x') %}"
_VALUE_BYTES = 262142 + 2  # the serialized JSON string, quotes included
_EXECUTION_CAP_BYTES = 10 * 1024 * 1024
_ITERATIONS = 60


def _execution_role(ctx):
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-sfnvarfree-")
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(_TRUST),
        Description="sim2real-behav: throwaway Step Functions execution role",
        Tags=[{"Key": "sim2real", "Value": "sfn-variable-space-freed"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    return arn


def _create_state_machine(ctx, definition, role_arn):
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-behav-sfnvarfree-sm-")
    deadline = time.monotonic() + 60
    while True:
        try:
            arn = sfn.create_state_machine(
                name=name,
                definition=json.dumps(definition),
                roleArn=role_arn,
                type="EXPRESS",
                tags=[{"key": "sim2real", "value": "sfn-variable-space-freed"}],
            )["stateMachineArn"]
            break
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code != "AccessDeniedException" or time.monotonic() >= deadline:
                raise
            time.sleep(2)
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
    return arn


def _run_sync(ctx, sm_arn):
    sfn = ctx.client("stepfunctions")
    return sfn.start_sync_execution(stateMachineArn=sm_arn, input="{}")


def _chain_of_distinct_assigns(n: int) -> dict:
    """n sequential Pass states, each assigning its OWN cap-sized variable -- nothing is freed."""
    states = {}
    for i in range(1, n + 1):
        states[f"S{i}"] = {
            "Type": "Pass",
            "Assign": {f"v{i}": _VALUE},
            "Next": f"S{i + 1}" if i < n else None,
        }
    states[f"S{n}"]["End"] = True
    del states[f"S{n}"]["Next"]
    return {"QueryLanguage": "JSONata", "StartAt": "S1", "States": states}


def _chain_of_reassigns(n: int) -> dict:
    """n sequential Pass states, every one reassigning the SAME variable name."""
    states = {}
    for i in range(1, n + 1):
        states[f"S{i}"] = {
            "Type": "Pass",
            "Assign": {"x": _VALUE},
            "Next": f"S{i + 1}" if i < n else None,
        }
    states[f"S{n}"]["End"] = True
    del states[f"S{n}"]["Next"]
    return {"QueryLanguage": "JSONata", "StartAt": "S1", "States": states}


def _map_of_local_assigns(n: int) -> dict:
    """A Map with n iterations, each assigning a cap-sized variable local to its own iteration."""
    return {
        "QueryLanguage": "JSONata",
        "StartAt": "DoMap",
        "States": {
            "DoMap": {
                "Type": "Map",
                "Items": f"{{% [1..{n}] %}}",
                "ItemProcessor": {
                    "ProcessorConfig": {"Mode": "INLINE"},
                    "StartAt": "Inner",
                    "States": {
                        "Inner": {"Type": "Pass", "Assign": {"localvar": _VALUE}, "End": True}
                    },
                },
                "End": True,
            }
        },
    }


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """The execution-wide variable-size cap tracks resident data, not a running sum: reassigning a
    variable frees the value it replaces, and a Map iteration's local variable is freed on exit,
    so either one lets past-the-cap gross data succeed where the same volume under fresh names fails.

    Reference: https://docs.aws.amazon.com/step-functions/latest/dg/workflow-variables.html
    """
    role_arn = _execution_role(ctx)

    # Baseline: the same gross volume, kept alive under distinct names, exceeds the cap.
    distinct_arn = _create_state_machine(ctx, _chain_of_distinct_assigns(_ITERATIONS), role_arn)
    distinct_resp = _run_sync(ctx, distinct_arn)
    assert distinct_resp["status"] == "FAILED", (
        f"{_ITERATIONS} distinct resident variables should exceed the execution cap, got "
        f"{distinct_resp!r}"
    )
    assert distinct_resp["error"] == "States.DataLimitExceeded", f"unexpected error: {distinct_resp!r}"
    # Each value serializes to _VALUE_BYTES, so 40 of them fill the 10 MiB execution cap
    # exactly and the 41st state's assignment exceeds it by its whole size.
    first_over = _EXECUTION_CAP_BYTES // _VALUE_BYTES + 1
    assert distinct_resp["cause"] == (
        f"Execution total variable size limit exceeded. State 'S{first_over}' assigned variables "
        f"that exceed the total execution limit by {_VALUE_BYTES} bytes."
    ), f"unexpected cause: {distinct_resp['cause']!r}"

    # Reassigning the same name that many times frees each prior value, so it succeeds.
    reassign_arn = _create_state_machine(ctx, _chain_of_reassigns(_ITERATIONS), role_arn)
    reassign_resp = _run_sync(ctx, reassign_arn)
    assert reassign_resp["status"] == "SUCCEEDED", (
        f"reassigning one variable {_ITERATIONS} times must free the prior value each time, got "
        f"{reassign_resp['status']!r} error={reassign_resp.get('error')!r} "
        f"cause={reassign_resp.get('cause')!r}"
    )

    # Assigning that many cap-sized variables inside separate Map iterations also succeeds: each
    # iteration's local variable is freed when the iteration ends.
    map_arn = _create_state_machine(ctx, _map_of_local_assigns(_ITERATIONS), role_arn)
    map_resp = _run_sync(ctx, map_arn)
    assert map_resp["status"] == "SUCCEEDED", (
        f"a Map iteration's local variable must be freed on exit, got {map_resp['status']!r} "
        f"error={map_resp.get('error')!r} cause={map_resp.get('cause')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
