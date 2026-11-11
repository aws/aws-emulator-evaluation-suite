"""e2e-order-processing-workflow."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-order-processing-workflow"
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
        tags=[{"key": "sim2real", "value": "1"}],
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


def _get_output(resp):
    raw = resp.get("output")
    return None if raw is None else json.loads(raw)

@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Order processing: Choice routes high-value orders to approval, low-value to shipping."""
    definition = {
        "StartAt": "validate_order",
        "States": {
            "validate_order": {
                "Type": "Pass",
                "Result": True,
                "ResultPath": "$.validated",
                "Next": "check_amount",
            },
            "check_amount": {
                "Type": "Choice",
                "Choices": [
                    {
                        "Variable": "$.amount",
                        "NumericGreaterThan": 100,
                        "Next": "require_approval",
                    },
                ],
                "Default": "ship_order",
            },
            "require_approval": {
                "Type": "Pass",
                "Result": "approval_required",
                "ResultPath": "$.decision",
                "Next": "complete",
            },
            "ship_order": {
                "Type": "Pass",
                "Result": "shipped",
                "ResultPath": "$.decision",
                "Next": "complete",
            },
            "complete": {
                "Type": "Succeed",
            },
        },
    }
    sm_arn = _create_state_machine(ctx, definition)
    # High-value order takes approval path
    exec_high = _start_execution(ctx, sm_arn, input_data={"orderId": "123", "amount": 150})
    result_high = _wait_execution_complete(ctx, exec_high)
    assert result_high["status"] == "SUCCEEDED", (
        f"expected SUCCEEDED for high-value execution, got {result_high['status']!r}"
    )
    output_high = _get_output(result_high)
    assert output_high["validated"] is True, (
        f"expected validated=True, got {output_high.get('validated')!r}"
    )
    assert output_high["decision"] == "approval_required", (
        f"expected decision='approval_required' for amount=150, got {output_high.get('decision')!r}"
    )
    assert output_high["orderId"] == "123", (
        f"expected orderId to pass through unchanged as '123', got {output_high.get('orderId')!r}"
    )

    # Low-value order takes ship path (reuse the same state machine)
    exec_arn = _start_execution(ctx, sm_arn, input_data={"orderId": "456", "amount": 50})
    result_low = _wait_execution_complete(ctx, exec_arn)
    assert result_low["status"] == "SUCCEEDED", (
        f"expected SUCCEEDED for low-value execution, got {result_low['status']!r}"
    )
    output_low = _get_output(result_low)
    assert output_low["decision"] == "shipped", (
        f"expected decision='shipped' for amount=50, got {output_low.get('decision')!r}"
    )
    assert output_low["orderId"] == "456", (
        f"expected orderId to pass through unchanged as '456', got {output_low.get('orderId')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
