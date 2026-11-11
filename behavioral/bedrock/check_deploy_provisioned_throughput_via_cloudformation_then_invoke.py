"""deploy-provisioned-throughput-via-cloudformation-then-invoke."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "deploy-provisioned-throughput-via-cloudformation-then-invoke"
GROUP = "server-side"
SERVICES = ["bedrock"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateStack rejects the nonexistent AWS::Bedrock::ProvisionedModelThroughput type.

    The rejection is a synchronous ValidationError naming the unrecognized type and leaves no
    stack behind; an AWS::Bedrock::Guardrail stack reaching CREATE_COMPLETE is the control.
    """
    cfn = ctx.client("cloudformation")

    # Positive control: a template using a resource type that really exists in
    # the AWS::Bedrock CloudFormation namespace deploys successfully.
    control_stack_name = ctx.unique_name("sim2real-bedrock-pt-control-")
    control_template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Guardrail": {
                "Type": "AWS::Bedrock::Guardrail",
                "Properties": {
                    "Name": ctx.unique_name("sim2real-bedrock-pt-ctrl-gr-"),
                    "BlockedInputMessaging": "This request was blocked by policy.",
                    "BlockedOutputsMessaging": "This response was blocked by policy.",
                    "ContentPolicyConfig": {
                        "FiltersConfig": [
                            {
                                "Type": "SEXUAL",
                                "InputStrength": "HIGH",
                                "OutputStrength": "HIGH",
                            }
                        ]
                    },
                },
            }
        },
    }

    def _cleanup_control_stack() -> None:
        from botocore.exceptions import ClientError

        cfn.delete_stack(StackName=control_stack_name)
        try:
            _wait_stack_status(cfn, control_stack_name, {"DELETE_COMPLETE"}, timeout_s=300.0)
        except ClientError as exc:
            # A fully deleted stack no longer resolves by name.
            if exc.response["Error"]["Code"] != "ValidationError":
                raise

    cfn.create_stack(
        StackName=control_stack_name, TemplateBody=json.dumps(control_template)
    )
    ctx.on_cleanup(_cleanup_control_stack)
    control_stack = _wait_stack_status(
        cfn, control_stack_name, {"CREATE_COMPLETE"}, timeout_s=300.0
    )
    assert control_stack["StackStatus"] == "CREATE_COMPLETE", control_stack["StackStatus"]

    # Negative: AWS::Bedrock::ProvisionedModelThroughput does not exist as a
    # CloudFormation resource type, so CreateStack must reject it up front.
    bad_stack_name = ctx.unique_name("sim2real-bedrock-pt-bad-")
    unsupported_type = "AWS::Bedrock::ProvisionedModelThroughput"
    bad_template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "ProvisionedThroughput": {
                "Type": unsupported_type,
                "Properties": {
                    "ModelId": "amazon.titan-text-express-v1",
                    "ModelUnits": 1,
                    "ProvisionedModelName": ctx.unique_name("sim2real-bedrock-pt-"),
                },
            }
        },
    }
    code, message = _error_code_and_message(
        lambda: cfn.create_stack(
            StackName=bad_stack_name, TemplateBody=json.dumps(bad_template)
        ),
        on_unexpected_success=lambda: ctx.on_cleanup(
            lambda: cfn.delete_stack(StackName=bad_stack_name)
        ),
    )
    expected = (
        "ValidationError",
        f"Template format error: Unrecognized resource types: [{unsupported_type}]",
    )
    assert (code, message) == expected, f"expected {expected!r}, got {(code, message)!r}"

    # Effect absent: the rejected CreateStack call must not have left any
    # stack (in any state) behind under that name.
    all_stack_names = {
        s["StackName"]
        for page in cfn.get_paginator("list_stacks").paginate()
        for s in page["StackSummaries"]
    }
    assert bad_stack_name not in all_stack_names, (
        f"CreateStack was rejected but a stack {bad_stack_name!r} still exists"
    )


def _wait_stack_status(
    cfn: Any,
    stack_name: str,
    target_statuses: set[str],
    timeout_s: float = 300.0,
    interval_s: float = 10.0,
) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        resp = cfn.describe_stacks(StackName=stack_name)
        stack = resp["Stacks"][0]
        last_status = stack["StackStatus"]
        if last_status in target_statuses:
            return stack
        if last_status.endswith("FAILED") or last_status == "ROLLBACK_COMPLETE":
            raise AssertionError(f"stack {stack_name} entered {last_status}")
        time.sleep(interval_s)
    raise AssertionError(
        f"stack {stack_name} did not reach {target_statuses}, last status {last_status}"
    )


def _error_code_and_message(
    fn, *, on_unexpected_success: Any = None
) -> tuple[str, str | None]:
    """Call fn(); return its botocore error code and message. An unexpected SUCCESS raises, because
    a target ACCEPTING input real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        error = exc.response["Error"]
        return error["Code"], error.get("Message", "")
    if on_unexpected_success is not None:
        on_unexpected_success()
    raise AssertionError(
        f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
