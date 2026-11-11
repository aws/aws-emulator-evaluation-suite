"""cfn-deploy-eventbridge-rule-lambda-target."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-deploy-eventbridge-rule-lambda-target"

GROUP = "deployment-order"

SERVICES = ["events", "lambda", "sqs"]

DEPLOYMENTS = Path(__file__).parent / "deployments"


def _outputs(result: dict) -> dict:
    """Deployment results may nest outputs under 'outputs' or expose them flat."""
    return result.get("outputs", result)


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:deploy", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """CloudFormation stack wiring EventBridge -> Lambda -> SQS reaches usable state."""
    template = (DEPLOYMENTS / "eventbridge-lambda.yaml").read_text()
    # Real-AWS CFN needs comfortably more than 100s to create the IAM role +
    # Lambda + rule + permission; use the harness default (300s) so the stack
    # can reach CREATE_COMPLETE instead of timing out mid-CREATE_IN_PROGRESS.
    result = _deploy_cfn(ctx, template)
    outputs = _outputs(result)
    queue_url = outputs["ResultQueueUrl"]
    fn_arn = outputs["FunctionArn"]
    rule_arn = outputs["RuleArn"]

    # Deployment must resolve cross-resource references into real ARNs.
    assert fn_arn.startswith("arn:aws:lambda:"), (
        f"expected FunctionArn output to start with 'arn:aws:lambda:', got {fn_arn!r}"
    )
    assert rule_arn.startswith("arn:aws:events:"), (
        f"expected RuleArn output to start with 'arn:aws:events:', got {rule_arn!r}"
    )

    # The rule's target must have been bound to the deployed function's ARN.
    events = ctx.client("events")
    rule_name = rule_arn.split("/")[-1]
    targets = events.list_targets_by_rule(Rule=rule_name)["Targets"]
    assert [t["Arn"] for t in targets] == [fn_arn], targets

    # AWS::Lambda::Permission must have produced a resource policy scoped to the rule.
    lambda_client = ctx.client("lambda")
    fn_name = fn_arn.split(":")[-1]
    policy = json.loads(lambda_client.get_policy(FunctionName=fn_name)["Policy"])
    principals = [s.get("Principal", {}).get("Service") for s in policy["Statement"]]
    assert "events.amazonaws.com" in principals, policy
    source_arns = [
        s.get("Condition", {}).get("ArnLike", {}).get("AWS:SourceArn")
        or s.get("Condition", {}).get("ArnEquals", {}).get("AWS:SourceArn")
        for s in policy["Statement"]
    ]
    assert rule_arn in source_arns, source_arns

    # The full chain must work end to end: a real event matching the rule's pattern
    # (source=custom.cfntest) must make EventBridge invoke the deployed function through the
    # deployed Lambda::Permission, which forwards the raw event to the stack's queue. Invoking
    # the function directly would never exercise the rule's pattern match or the resource
    # policy asserted above.
    correlation_id = ctx.unique_name("cfn-probe-")
    ctx.client("events").put_events(
        Entries=[
            {
                "Source": "custom.cfntest",
                "DetailType": "cfn-probe",
                "Detail": json.dumps({"probe": "cfn", "correlation_id": correlation_id}),
            }
        ]
    )
    delivered = _poll_for_correlated_event(ctx, queue_url, correlation_id, timeout_s=60.0)
    assert delivered["source"] == "custom.cfntest", (
        f"expected forwarded event source 'custom.cfntest', got {delivered.get('source')!r}"
    )
    assert delivered["detail"]["probe"] == "cfn", (
        f"expected forwarded event detail.probe 'cfn', got "
        f"{delivered.get('detail', {}).get('probe')!r}"
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


def _poll_for_correlated_event(ctx, queue_url, correlation_id, *, timeout_s=60.0):
    """Poll SQS for the raw EventBridge envelope whose detail.correlation_id matches;
    drain and discard anything else. Returns the matching body (raises on timeout)."""
    sqs = ctx.client("sqs")

    def _probe():
        resp = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5
        )
        for msg in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            body = json.loads(msg["Body"])
            if body.get("detail", {}).get("correlation_id") == correlation_id:
                return body
        return None

    return _poll_until(
        _probe,
        lambda r: r is not None,
        timeout_s=timeout_s,
        interval_s=2.0,
        description=f"event {correlation_id} forwarded to queue",
    )


def _delete_stack_and_wait(ctx, stack_name: str) -> None:
    """Delete a CFN stack and wait for DELETE_COMPLETE (teardown; errors swallowed by on_cleanup)."""
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)

    def _status():
        try:
            return cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            if not (
                (exc.response["Error"]["Code"] == "ValidationError" and "does not exist" in exc.response["Error"].get("Message", ""))
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
