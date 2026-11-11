"""cfn-deploy-missing-sfn-permission-negative."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-deploy-missing-sfn-permission-negative"

GROUP = "overly-permissive"

SERVICES = ["lambda", "s3", "stepfunctions"]

DEPLOYMENTS = Path(__file__).parent / "deployments"


@tags(
    "axis:rejection",
    "cap:c3",
    "cap:c7",
    "concern:data-plane",
    "concern:deploy",
    "concern:e2e",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """Deploy CFN stack with Lambda role missing states:StartExecution; verify AccessDeniedException,
    then grant the missing permission on the SAME CFN-created role (in-file positive control) and
    demand an identical invocation now starts and completes a real execution."""
    template_path = DEPLOYMENTS / "broken-sfn-perms.yaml"
    assert template_path.is_file(), (
        f"deployment artifact missing on disk: {template_path}"
    )
    template = template_path.read_text()
    result = _deploy_cfn(ctx, template)
    outputs = result["outputs"]
    function_name = outputs["FunctionName"]
    lambda_role_name = outputs["LambdaRoleName"]
    state_machine_arn = outputs["StateMachineArn"]

    lam = ctx.client("lambda")
    resp = lam.invoke(
        FunctionName=function_name, Payload=json.dumps({"test": True}).encode()
    )
    payload = json.loads(resp["Payload"].read())
    payload_str = json.dumps(payload).lower()
    assert "accessdenied" in payload_str or "not authorized" in payload_str, (
        f"Expected AccessDeniedException but got: {payload}"
    )
    # Verify no execution was created
    sfn = ctx.client("stepfunctions")
    execs = sfn.list_executions(stateMachineArn=state_machine_arn)
    assert len(execs.get("executions", [])) == 0, (
        "Execution should not have been created"
    )

    # Positive control: grant the missing permission on the SAME CFN-created role, then demand an
    # identical invocation now succeeds. Without this, "denied because of a missing permission" is
    # indistinguishable from "denied because the deployment is broken in some unrelated way".
    iam = ctx.client("iam")
    policy_name = ctx.unique_name("sfn-startexec-policy")
    iam.put_role_policy(
        RoleName=lambda_role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "states:StartExecution",
                        "Resource": state_machine_arn,
                    }
                ],
            }
        ),
    )
    # Registered AFTER _deploy_cfn's stack-delete cleanup, so LIFO teardown removes this inline
    # policy FIRST -- the CFN-managed role would otherwise refuse deletion while it still holds a
    # policy CloudFormation doesn't know about, and the stack would end in DELETE_FAILED.
    ctx.on_cleanup(
        lambda: iam.delete_role_policy(
            RoleName=lambda_role_name, PolicyName=policy_name
        )
    )

    def _try_invoke():
        r = lam.invoke(
            FunctionName=function_name, Payload=json.dumps({"test": True}).encode()
        )
        return json.loads(r["Payload"].read())

    # IAM policy attachment is eventually consistent; retry the whole invocation.
    allowed_payload = _poll_until(
        _try_invoke,
        lambda p: p.get("status") == "started",
        timeout_s=60,
        interval_s=5.0,
        description="invocation succeeds after granting states:StartExecution",
    )
    exec_arn = allowed_payload["executionArn"]

    status = _poll_until(
        lambda: sfn.describe_execution(executionArn=exec_arn)["status"],
        lambda s: s in {"SUCCEEDED", "FAILED", "TIMED_OUT", "ABORTED"},
        timeout_s=30,
        interval_s=2.0,
        description="execution terminal (allowed)",
    )
    assert status == "SUCCEEDED", f"Expected SUCCEEDED but got: {status}"
    execs_after = sfn.list_executions(stateMachineArn=state_machine_arn)
    assert exec_arn in {e["executionArn"] for e in execs_after.get("executions", [])}, (
        f"Granted execution {exec_arn} not visible in list_executions: {execs_after}"
    )


_XSVC_PREFIX = "sim2real-xsvc-"

_MANAGED_TAG_KEY = "sim2real:managed"


def _xsvc_resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _xname(ctx: Any, kind: str) -> str:
    """A unique, prefix-tagged resource name: sim2real-xsvc-<kind>-<uuid>."""
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _poll_until(
    probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"
):
    """Poll probe() until predicate(result) is truthy; return the final result (raises on timeout)."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"{description} not met within {timeout_s}s. Last result: {last!r}"
    )


def _delete_stack_and_wait(ctx, stack_name: str) -> None:
    """Delete a CFN stack and wait for DELETE_COMPLETE (teardown; errors swallowed by on_cleanup)."""
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)

    def _status():
        try:
            return cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            err = exc.response["Error"]
            if err["Code"] != "StackNotFoundException" and not (
                err["Code"] == "ValidationError" and "does not exist" in err.get("Message", "")
            ):
                raise
            return 'GONE'

    _poll_until(
        _status,
        lambda s: s in {"DELETE_COMPLETE", "GONE"},
        timeout_s=120,
        interval_s=5.0,
        description=f"delete stack {stack_name}",
    )


def _deploy_cfn(
    ctx,
    template,
    *,
    stack_name=None,
    parameters=None,
    capabilities=None,
    timeout_s=300.0,
) -> dict[str, Any]:
    """Deploy a CloudFormation stack (template body str or Path); wait for CREATE_COMPLETE;
    register delete-stack-and-wait teardown. Returns {stack_name,stack_id,outputs:{k:v}}."""
    ctx.verify_account_safety()
    cfn = ctx.client("cloudformation")
    name = stack_name or _xname(ctx, "stk")
    template_body = template.read_text() if isinstance(template, Path) else template
    kwargs: dict[str, Any] = {
        "StackName": name,
        "TemplateBody": template_body,
        "Tags": _xsvc_tags_kv(),
        "Capabilities": capabilities or ["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
    }
    if parameters:
        kwargs["Parameters"] = [
            {"ParameterKey": k, "ParameterValue": v} for k, v in parameters.items()
        ]
    stack_id = cfn.create_stack(**kwargs)["StackId"]
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, name))
    _poll_until(
        lambda: cfn.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"],
        lambda s: (
            s
            in {
                "CREATE_COMPLETE",
                "CREATE_FAILED",
                "ROLLBACK_COMPLETE",
                "ROLLBACK_FAILED",
            }
        ),
        timeout_s=timeout_s,
        interval_s=5.0,
        description=f"CFN stack {name}",
    )
    stack = cfn.describe_stacks(StackName=name)["Stacks"][0]
    if stack["StackStatus"] != "CREATE_COMPLETE":
        raise AssertionError(f"Stack {name} ended in {stack['StackStatus']}")
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}
    return {"stack_name": name, "stack_id": stack_id, "outputs": outputs}


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
