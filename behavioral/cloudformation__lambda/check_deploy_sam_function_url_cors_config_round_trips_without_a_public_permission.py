"""deploy-sam-function-url-cors-config-round-trips-without-a-public-permission."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-sam-function-url-cors-config-round-trips-without-a-public-permission"
GROUP = "deploy"
SERVICES = ["cloudformation", "lambda"]

_SETTLE_S = 300.0

_TEMPLATE = """\
Transform: AWS::Serverless-2016-10-31
Parameters:
  FunctionName:
    Type: String
Resources:
  Fn:
    Type: AWS::Serverless::Function
    Properties:
      FunctionName: !Ref FunctionName
      Runtime: python3.13
      Handler: index.handler
      InlineCode: |
        def handler(event, context):
            return {"statusCode": 200, "body": "ok"}
      FunctionUrlConfig:
        AuthType: AWS_IAM
        Cors:
          AllowOrigins:
            - https://example.com
          AllowMethods:
            - GET
          MaxAge: 300
Outputs:
  FunctionUrl:
    Value: !GetAtt FnUrl.FunctionUrl
"""


def _poll(probe, ready, *, budget_s: float, interval_s: float = 2.0, what: str = "condition"):
    """probe() until ready(value); raises naming the last value once budget_s runs out."""
    deadline = time.monotonic() + budget_s
    while True:
        value = probe()
        if ready(value):
            return value
        if time.monotonic() >= deadline:
            raise AssertionError(f"{what} not reached within {budget_s}s; last saw {value!r}")
        time.sleep(interval_s)


def _stack_status(cfn, stack: str) -> str:
    """The stack's status, or DELETE_COMPLETE once CloudFormation has forgotten it."""
    try:
        return cfn.describe_stacks(StackName=stack)["Stacks"][0]["StackStatus"]
    except ClientError as exc:
        if f"Stack with id {stack} does not exist" == exc.response["Error"].get("Message"):
            return "DELETE_COMPLETE"
        raise


def _settle(cfn, stack: str) -> str:
    return _poll(lambda: _stack_status(cfn, stack), lambda s: not s.endswith("_IN_PROGRESS"),
                 budget_s=_SETTLE_S, what=f"stack {stack} settled")


def _stack_failures(cfn, stack: str) -> list:
    """(logical id, reason) of every failed resource event, quoted in a failing assert."""
    events: list = []
    for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack):
        events.extend(page["StackEvents"])
    return [(e["LogicalResourceId"], e.get("ResourceStatusReason")) for e in events
            if e["ResourceStatus"].endswith("_FAILED")]


def _change_set_outcome(cfn, stack: str, name: str) -> tuple:
    d = cfn.describe_change_set(StackName=stack, ChangeSetName=name)
    return d["Status"], d.get("StatusReason")


def _delete_stack(cfn, stack: str) -> None:
    status = _stack_status(cfn, stack)
    if status == "DELETE_COMPLETE":
        return
    if status.endswith("_IN_PROGRESS"):
        _settle(cfn, stack)
    cfn.delete_stack(StackName=stack)
    final = _poll(lambda: _stack_status(cfn, stack), lambda s: s in ("DELETE_COMPLETE", "DELETE_FAILED"),
                  budget_s=_SETTLE_S, what=f"stack {stack} deleted")
    assert final == "DELETE_COMPLETE", f"stack {stack} ended {final}: {_stack_failures(cfn, stack)!r}"


@tags("axis:happy-path", "cap:c1", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A SAM function's FunctionUrlConfig.Cors deploys as the exact origins, methods and max age
    requested; the generated AWS::Lambda::Url carries no AWS::Lambda::Permission beside it, and the
    output GetAtt equals the live config's FunctionUrl.

    Reference: https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/sam-specification-generated-resources-function.html
    """
    cfn = ctx.client("cloudformation")
    lam = ctx.client("lambda")

    fn = ctx.unique_name("sim2real-xsvc-corsurl-")
    stack = ctx.unique_name("sim2real-xsvc-corsurl-")
    change_set = ctx.unique_name("sim2real-xsvc-corsurl-cs-")

    cfn.create_change_set(
        StackName=stack, ChangeSetName=change_set, TemplateBody=_TEMPLATE, ChangeSetType="CREATE",
        Parameters=[{"ParameterKey": "FunctionName", "ParameterValue": fn}],
        Capabilities=["CAPABILITY_IAM", "CAPABILITY_AUTO_EXPAND"],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack))

    cs_status, cs_reason = _poll(
        lambda: _change_set_outcome(cfn, stack, change_set),
        lambda sr: sr[0] not in ("CREATE_PENDING", "CREATE_IN_PROGRESS"),
        budget_s=120.0, what="change set created",
    )
    assert cs_status == "CREATE_COMPLETE", f"change set ended {cs_status}: {cs_reason}"

    cfn.execute_change_set(StackName=stack, ChangeSetName=change_set)
    stack_status = _settle(cfn, stack)
    assert stack_status == "CREATE_COMPLETE", (
        f"stack ended {stack_status}: {_stack_failures(cfn, stack)!r}"
    )

    outputs = {o["OutputKey"]: o["OutputValue"]
               for o in cfn.describe_stacks(StackName=stack)["Stacks"][0]["Outputs"]}
    output_url = outputs["FunctionUrl"]

    resources = cfn.describe_stack_resources(StackName=stack)["StackResources"]
    types_by_logical_id = {r["LogicalResourceId"]: r["ResourceType"] for r in resources}
    assert types_by_logical_id.get("FnUrl") == "AWS::Lambda::Url", (
        f"the generated Url resource must be logical id FnUrl of type AWS::Lambda::Url; "
        f"saw {types_by_logical_id!r}"
    )
    assert types_by_logical_id.get("Fn") == "AWS::Lambda::Function", (
        f"the function itself must be logical id Fn of type AWS::Lambda::Function; "
        f"saw {types_by_logical_id!r}"
    )
    assert "AWS::Lambda::Permission" not in types_by_logical_id.values(), (
        f"an AWS_IAM function URL must generate no public-permission resource; "
        f"saw resource types {sorted(types_by_logical_id.values())!r}"
    )

    config = lam.get_function_url_config(FunctionName=fn)
    assert config["AuthType"] == "AWS_IAM", f"the deployed URL config must be AWS_IAM; got {config!r}"
    assert config["FunctionUrl"] == output_url, (
        f"the stack output GetAtt FnUrl.FunctionUrl must equal the live config's FunctionUrl; "
        f"output {output_url!r}, live {config['FunctionUrl']!r}"
    )
    cors = config["Cors"]
    assert cors["AllowOrigins"] == ["https://example.com"], (
        f"Cors.AllowOrigins must round-trip the one origin the template declared; got {cors!r}"
    )
    assert cors["AllowMethods"] == ["GET"], (
        f"Cors.AllowMethods must round-trip the one method the template declared; got {cors!r}"
    )
    assert cors["MaxAge"] == 300, f"Cors.MaxAge must round-trip the template's 300; got {cors!r}"

    _delete_stack(cfn, stack)

    try:
        gone = lam.get_function(FunctionName=fn)
    except ClientError as exc:
        err = (exc.response["Error"]["Code"], exc.response["Error"].get("Message"))
        assert err == (
            "ResourceNotFoundException",
            f"Function not found: arn:aws:lambda:{ctx.region}:{ctx.account}:function:{fn}",
        ), f"GetFunction after the stack delete must name the function's own ARN; got {err!r}"
    else:
        raise AssertionError(f"function {fn!r} survived the stack delete: {gone!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
