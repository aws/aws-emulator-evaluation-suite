"""e2e-fan-out-aggregate."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-fan-out-aggregate"
GROUP = 'e2e_workflows'
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
    )["stateMachineArn"]
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
    return arn


def _start_execution(ctx, sm_arn, *, input_data=None, name=None):
    sfn = ctx.client("stepfunctions")
    kwargs = {"stateMachineArn": sm_arn}
    if input_data is not None:
        kwargs["input"] = json.dumps(input_data)
    if name is not None:
        kwargs["name"] = name
    exec_arn = sfn.start_execution(**kwargs)["executionArn"]
    ctx.on_cleanup(lambda: sfn.stop_execution(executionArn=exec_arn))
    return exec_arn


def _wait_execution_complete(ctx, exec_arn, *, timeout_s=30):
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = sfn.describe_execution(executionArn=exec_arn)
        if last["status"] in ("SUCCEEDED", "FAILED", "TIMED_OUT", "ABORTED"):
            return last
        time.sleep(0.5)
    raise AssertionError(f"execution {exec_arn} not terminal within {timeout_s}s: {last!r}")


def _run_to_completion(ctx, definition, input_data=None, *, timeout_s=30):
    arn = _create_state_machine(ctx, definition)
    exec_arn = _start_execution(ctx, arn, input_data=input_data)
    return _wait_execution_complete(ctx, exec_arn, timeout_s=timeout_s)


def _get_output(resp):
    raw = resp.get("output")
    return None if raw is None else json.loads(raw)

@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Fan-out/aggregate: Parallel with 3 branches producing different data, combined in output."""
    definition = {
        "StartAt": "scatter",
        "States": {
            "scatter": {
                "Type": "Parallel",
                "Branches": [
                    {
                        "StartAt": "fetch_inventory",
                        "States": {
                            "fetch_inventory": {
                                "Type": "Pass",
                                "Result": {"source": "inventory", "count": 42},
                                "End": True,
                            }
                        },
                    },
                    {
                        "StartAt": "fetch_pricing",
                        "States": {
                            "fetch_pricing": {
                                "Type": "Pass",
                                "Result": {"source": "pricing", "price": 9.99},
                                "End": True,
                            }
                        },
                    },
                    {
                        "StartAt": "fetch_reviews",
                        "States": {
                            "fetch_reviews": {
                                "Type": "Pass",
                                "Result": {"source": "reviews", "rating": 4.5},
                                "End": True,
                            }
                        },
                    },
                ],
                "ResultPath": "$.results",
                "Next": "gather",
            },
            "gather": {
                "Type": "Pass",
                "End": True,
            },
        },
    }
    result = _run_to_completion(ctx, definition, {"productId": "prod-1"})
    assert result["status"] == "SUCCEEDED", (
        f"fan-out execution must succeed, got {result.get('status')} cause={result.get('cause')}"
    )
    output = _get_output(result)
    # The parallel output is an array of 3 branch results stored at $.results
    assert isinstance(output["results"], list), f"expected $.results to be a list, got {output!r}"
    assert len(output["results"]) == 3, f"expected 3 branch results, got {output['results']!r}"
    # Branch order in the output must match branch DEFINITION position, not completion order —
    # a set comparison here would pass a target that scrambles results across branches.
    assert output["results"] == [
        {"source": "inventory", "count": 42},
        {"source": "pricing", "price": 9.99},
        {"source": "reviews", "rating": 4.5},
    ], f"expected branch results positionally ordered by definition, got {output['results']!r}"
    # Original input is preserved
    assert output["productId"] == "prod-1", f"expected productId 'prod-1' preserved, got {output!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
