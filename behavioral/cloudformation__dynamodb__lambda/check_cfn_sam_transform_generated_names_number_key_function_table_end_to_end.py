"""cfn-sam-transform-generated-names-number-key-function-table-end-to-end."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-sam-transform-generated-names-number-key-function-table-end-to-end"

GROUP = "deployment-order"

SERVICES = ["cloudformation", "dynamodb", "lambda"]

#: Only AWS::Serverless::* resources, no names and a Number key: the transform must generate the
#: table, function and role names, and DynamoDBCrudPolicy must reach the generated table.
_TEMPLATE = """
AWSTemplateFormatVersion: '2010-09-09'
Transform: AWS::Serverless-2016-10-31
Description: SAM SimpleTable with a Number key and an unnamed function

Resources:
  Ledger:
    Type: AWS::Serverless::SimpleTable
    Properties:
      PrimaryKey:
        Name: entry_id
        Type: Number

  Recorder:
    Type: AWS::Serverless::Function
    Properties:
      Runtime: python3.12
      Handler: index.handler
      Timeout: 30
      MemorySize: 256
      Environment:
        Variables:
          LEDGER: !Ref Ledger
      Policies:
        - DynamoDBCrudPolicy:
            TableName: !Ref Ledger
      InlineCode: |
        import os

        import boto3

        ddb = boto3.client('dynamodb')


        def handler(event, context):
            table = os.environ['LEDGER']
            ddb.put_item(
                TableName=table,
                Item={'entry_id': {'N': event['entry_id']}, 'memo': {'S': event['memo']},
                      'tags': {'SS': event['tags']}},
            )
            return {'table': table}

Outputs:
  LedgerName:
    Value: !Ref Ledger
  RecorderName:
    Value: !Ref Recorder
  RecorderArn:
    Value: !GetAtt Recorder.Arn
"""


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "concern:deploy", "concern:e2e", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """With no names given, the SAM transform generates the table, function and role: the outputs
    match the stack's physical ids, the table is keyed on a Number, and the invoked function's write
    is read back by the canonical form of the number it was sent.
    """
    cfn = ctx.client("cloudformation")
    ddb = ctx.client("dynamodb")
    awslambda = ctx.client("lambda")

    result = _deploy_cfn(ctx, _TEMPLATE, capabilities=["CAPABILITY_AUTO_EXPAND", "CAPABILITY_IAM"], timeout_s=900.0)
    stack_name = result["stack_name"]
    outputs = _outputs(result)
    table_name, function_name = outputs["LedgerName"], outputs["RecorderName"]
    ctx.on_cleanup(lambda: _delete_log_group_if_present(ctx, f"/aws/lambda/{function_name}"))

    resources = {r["LogicalResourceId"]: (r["ResourceType"], r["PhysicalResourceId"])
                 for r in cfn.list_stack_resources(StackName=stack_name)["StackResourceSummaries"]}
    assert resources["Ledger"] == ("AWS::DynamoDB::Table", table_name), resources
    assert resources["Recorder"] == ("AWS::Lambda::Function", function_name), resources
    assert resources["RecorderRole"][0] == "AWS::IAM::Role", (
        f"the transform must generate RecorderRole for a function without a Role, got {sorted(resources)}"
    )
    assert not any(t.startswith("AWS::Serverless::") for t, _ in resources.values()), resources

    described = ddb.describe_table(TableName=table_name)["Table"]
    assert described["KeySchema"] == [{"AttributeName": "entry_id", "KeyType": "HASH"}], described["KeySchema"]
    assert described["AttributeDefinitions"] == [{"AttributeName": "entry_id", "AttributeType": "N"}], (
        f"a Number PrimaryKey must become AttributeType N, got {described['AttributeDefinitions']}"
    )

    memo = _xname(ctx, "sam-memo")
    payload = _invoke_json(awslambda, function_name, {"entry_id": "0042.500", "memo": memo, "tags": ["b", "c", "a"]})
    assert payload == {"table": table_name}, payload
    # The function has returned, so a consistent read sees its write; a bounded poll, graded on its last answer.
    deadline = time.monotonic() + 30.0
    while True:
        item = ddb.get_item(TableName=table_name, Key={"entry_id": {"N": "42.5"}}, ConsistentRead=True).get("Item")
        if item or time.monotonic() >= deadline:
            break
        time.sleep(2.0)
    assert item, f"GetItem entry_id 42.5: expected the recorded item, got {item!r}"
    assert (item["entry_id"], item["memo"]) == ({"N": "42.5"}, {"S": memo}), (
        f"expected entry_id N 42.5 and memo {memo!r}, got {item!r}"
    )
    assert sorted(item["tags"]["SS"]) == ["a", "b", "c"], f"the string set must hold its three members, got {item['tags']!r}"

    configured = awslambda.get_function_configuration(FunctionName=function_name)
    assert outputs["RecorderArn"] == configured["FunctionArn"], (outputs["RecorderArn"], configured["FunctionArn"])
    assert configured["Role"].endswith("/" + resources["RecorderRole"][1]), (
        f"the function's role must be the generated RecorderRole, got {configured['Role']!r}"
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
    probe, predicate, *, timeout_s=40.0, interval_s=1.0, description="condition"
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


def _delete_log_group_if_present(ctx, log_group: str) -> None:
    """Delete the log group, tolerating only not-found: an uninvoked function has none."""
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
    register delete-stack-and-wait teardown. Returns {stack_name,stack_id,outputs:{k:v}}.
    """
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
