"""cfn-sam-transform-function-table-end-to-end."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-sam-transform-function-table-end-to-end"

GROUP = "deployment-order"

SERVICES = ["cloudformation", "dynamodb", "lambda"]

DEPLOYMENTS = Path(__file__).parent / "deployments"


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "concern:deploy", "concern:e2e", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """The SAM transform expands AWS::Serverless::Function/SimpleTable into a Lambda function, a
    DynamoDB table keyed on pk and a generated role: the invoked function writes an item that
    DynamoDB GetItem returns, which works only if the transform synthesized the role."""
    cfn = ctx.client("cloudformation")
    ddb = ctx.client("dynamodb")
    awslambda = ctx.client("lambda")

    table_name = _xname(ctx, "sam-items")
    function_name = _xname(ctx, "sam-writer")

    # Registered BEFORE the deploy so LIFO runs it AFTER the stack delete: a belt-and-braces
    # sweep for the case where the stack delete leaves the table behind.
    ctx.on_cleanup(lambda: _delete_table_if_present(ddb, table_name))
    # The function's log group is NOT the stack's to remove. Lambda creates /aws/lambda/<name> on
    # first invocation, the template never declares it, and CloudFormation deletes only what it
    # owns -- so DELETE_COMPLETE leaves the group behind. Registered here, before the deploy, so
    # LIFO runs it after the stack (and
    # therefore the function) is gone and Lambda cannot recreate it underneath us.
    ctx.on_cleanup(
        lambda: _delete_log_group_if_present(ctx, f"/aws/lambda/{function_name}")
    )

    result = _deploy_cfn(
        ctx,
        (DEPLOYMENTS / "sam-function-table.yaml").read_text(),
        parameters={"TableName": table_name, "FunctionName": function_name},
        capabilities=["CAPABILITY_AUTO_EXPAND", "CAPABILITY_IAM"],
        timeout_s=900.0,
    )
    stack_name = result["stack_name"]
    outputs = _outputs(result)

    # 1. The transform expanded into concrete resource types, including a role it invented.
    resources = cfn.list_stack_resources(StackName=stack_name)["StackResourceSummaries"]
    types = {r["ResourceType"] for r in resources}
    for expected in ("AWS::Lambda::Function", "AWS::DynamoDB::Table", "AWS::IAM::Role"):
        assert expected in types, (
            f"SAM expansion produced {sorted(types)}; {expected} is missing (a template that "
            "declares only AWS::Serverless::* resources must expand into concrete types)"
        )
    assert not any(t.startswith("AWS::Serverless::") for t in types), (
        f"AWS::Serverless::* types survived into the deployed stack: {sorted(types)}"
    )

    # 2. Ref of a SimpleTable is the table name, and the table really has the declared key.
    assert outputs["TableNameOut"] == table_name, (
        f"Ref of the SimpleTable returned {outputs['TableNameOut']!r}, expected {table_name!r}"
    )
    described = ddb.describe_table(TableName=table_name)["Table"]
    assert described["KeySchema"] == [{"AttributeName": "pk", "KeyType": "HASH"}], (
        f"PrimaryKey Name/Type did not become the table's key schema: {described['KeySchema']}"
    )
    assert {"AttributeName": "pk", "AttributeType": "S"} in described[
        "AttributeDefinitions"
    ], described["AttributeDefinitions"]

    # 3. The generated function runs, and the generated role lets it write to the table.
    note = _xname(ctx, "sam-note")
    payload = _invoke_json(
        awslambda, outputs["WriterFunctionName"], {"pk": "item-1", "note": note}
    )
    assert payload["table"] == table_name, payload
    assert payload["note"] == note, payload

    item = _poll_until(
        lambda: ddb.get_item(
            TableName=table_name, Key={"pk": {"S": "item-1"}}, ConsistentRead=True
        ).get("Item"),
        lambda i: bool(i),
        timeout_s=60.0,
        interval_s=2.0,
        description=f"item written by {function_name} visible in {table_name}",
    )
    assert item["note"] == {"S": note}, (
        f"item in DynamoDB is {item!r}; the SAM-generated role must permit dynamodb:PutItem "
        "with the exact payload the function sent"
    )

    # 4. GetAtt Arn on a serverless function must be the real function's ARN.
    configured = awslambda.get_function_configuration(
        FunctionName=outputs["WriterFunctionName"]
    )
    assert outputs["WriterArn"] == configured["FunctionArn"], (
        f"GetAtt Arn returned {outputs['WriterArn']!r}, Lambda reports "
        f"{configured['FunctionArn']!r}"
    )
    assert configured["Environment"]["Variables"]["TABLE_NAME"] == table_name, configured
    assert configured.get("Role"), (
        "the expanded function has no execution role; SAM must generate one from Policies"
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


def _outputs(result: dict) -> dict:
    """Deployment results may nest outputs under 'outputs' or expose them flat."""
    return result.get("outputs", result)


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


def _invoke_json(awslambda, function_name: str, payload: dict) -> dict:
    """Synchronously invoke a Lambda and decode its JSON result (asserting no function error)."""
    response = awslambda.invoke(
        FunctionName=function_name,
        InvocationType="RequestResponse",
        Payload=json.dumps(payload).encode(),
    )
    body = response["Payload"].read().decode()
    assert not response.get("FunctionError"), f"{function_name} failed: {body}"
    return json.loads(body)


def _delete_table_if_present(ddb, table_name: str) -> None:
    """Best-effort table teardown; a table the stack already removed is not an error."""
    try:
        ddb.delete_table(TableName=table_name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


def _delete_log_group_if_present(ctx, log_group: str) -> None:
    """Best-effort log-group teardown; a group Lambda never got round to creating is not an error."""
    try:
        ctx.client("logs").delete_log_group(logGroupName=log_group)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


def _delete_stack_and_wait(ctx, stack_name: str, *, timeout_s=600.0) -> None:
    """Delete a CFN stack and wait for DELETE_COMPLETE; only a stack that does not exist counts as gone."""
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)

    def _status():
        try:
            return cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            if "does not exist" not in exc.response["Error"].get("Message", ""):
                raise
            return "GONE"

    _poll_until(
        _status,
        lambda s: s in {"DELETE_COMPLETE", "GONE"},
        timeout_s=timeout_s,
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
    timeout_s=600.0,
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
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, name, timeout_s=timeout_s))
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
