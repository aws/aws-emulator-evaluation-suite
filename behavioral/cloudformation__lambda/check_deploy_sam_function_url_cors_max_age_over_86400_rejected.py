"""deploy-sam-function-url-cors-max-age-over-86400-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-sam-function-url-cors-max-age-over-86400-rejected"
GROUP = "deploy"
SERVICES = ["cloudformation", "lambda"]

_SETTLE_S = 300.0

_TEMPLATE = """\
Transform: AWS::Serverless-2016-10-31
Parameters:
  FunctionName:
    Type: String
  MaxAge:
    Type: Number
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
          MaxAge: !Ref MaxAge
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
    events: list = []
    for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack):
        events.extend(page["StackEvents"])
    return [(e["LogicalResourceId"], e.get("ResourceStatusReason")) for e in events
            if e["ResourceStatus"].endswith("_FAILED")]


def _change_set_outcome(cfn, stack: str, name: str) -> tuple:
    d = cfn.describe_change_set(StackName=stack, ChangeSetName=name)
    return d["Status"], d.get("StatusReason")


def _validation_errors(cfn, stack: str, change_set: str) -> list:
    """Every VALIDATION_ERROR event DescribeEvents recorded for the change set's early validation."""
    events: list = []
    for page in cfn.get_paginator("describe_events").paginate(
        StackName=stack, ChangeSetName=change_set
    ):
        events.extend(page["OperationEvents"])
    return [e for e in events if e["EventType"] == "VALIDATION_ERROR"]


def _delete_stack(cfn, stack: str) -> None:
    """Delete by name and wait for DELETE_COMPLETE; a stack stuck reviewing a change set deletes
    straight away, since CloudFormation never advances REVIEW_IN_PROGRESS on its own."""
    status = _stack_status(cfn, stack)
    if status == "DELETE_COMPLETE":
        return
    if status.endswith("_IN_PROGRESS") and status != "REVIEW_IN_PROGRESS":
        _settle(cfn, stack)
    cfn.delete_stack(StackName=stack)
    final = _poll(lambda: _stack_status(cfn, stack), lambda s: s in ("DELETE_COMPLETE", "DELETE_FAILED"),
                  budget_s=_SETTLE_S, what=f"stack {stack} deleted")
    assert final == "DELETE_COMPLETE", f"stack {stack} ended {final}: {_stack_failures(cfn, stack)!r}"


@tags("axis:rejection", "cap:c1", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A SAM FunctionUrlConfig.Cors.MaxAge of 86401 fails the deploy's early property validation
    naming the documented 86400-second ceiling and creates no function; 86400 itself deploys.

    Reference: https://docs.aws.amazon.com/lambda/latest/api/API_Cors.html
    """
    cfn = ctx.client("cloudformation")
    lam = ctx.client("lambda")

    good_fn = ctx.unique_name("sim2real-xsvc-corsage-ok-")
    good_stack = ctx.unique_name("sim2real-xsvc-corsage-ok-")
    good_cs = ctx.unique_name("sim2real-xsvc-corsage-ok-cs-")

    cfn.create_change_set(
        StackName=good_stack, ChangeSetName=good_cs, TemplateBody=_TEMPLATE, ChangeSetType="CREATE",
        Parameters=[{"ParameterKey": "FunctionName", "ParameterValue": good_fn},
                    {"ParameterKey": "MaxAge", "ParameterValue": "86400"}],
        Capabilities=["CAPABILITY_IAM", "CAPABILITY_AUTO_EXPAND"],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_stack(cfn, good_stack))
    good_cs_status, good_cs_reason = _poll(
        lambda: _change_set_outcome(cfn, good_stack, good_cs),
        lambda sr: sr[0] not in ("CREATE_PENDING", "CREATE_IN_PROGRESS"),
        budget_s=120.0, what="control change set created",
    )
    assert good_cs_status == "CREATE_COMPLETE", (
        f"a MaxAge of 86400, the documented ceiling, must pass early validation; "
        f"change set ended {good_cs_status!r}: {good_cs_reason!r}"
    )
    cfn.execute_change_set(StackName=good_stack, ChangeSetName=good_cs)
    good_stack_status = _settle(cfn, good_stack)
    assert good_stack_status == "CREATE_COMPLETE", (
        f"a MaxAge of 86400 must deploy; stack ended {good_stack_status!r}: "
        f"{_stack_failures(cfn, good_stack)!r}"
    )
    good_config = lam.get_function_url_config(FunctionName=good_fn)
    assert good_config["Cors"]["MaxAge"] == 86400, (
        f"the control's deployed MaxAge must be 86400; got {good_config!r}"
    )

    bad_fn = ctx.unique_name("sim2real-xsvc-corsage-bad-")
    bad_stack = ctx.unique_name("sim2real-xsvc-corsage-bad-")
    bad_cs = ctx.unique_name("sim2real-xsvc-corsage-bad-cs-")

    cfn.create_change_set(
        StackName=bad_stack, ChangeSetName=bad_cs, TemplateBody=_TEMPLATE, ChangeSetType="CREATE",
        Parameters=[{"ParameterKey": "FunctionName", "ParameterValue": bad_fn},
                    {"ParameterKey": "MaxAge", "ParameterValue": "86401"}],
        Capabilities=["CAPABILITY_IAM", "CAPABILITY_AUTO_EXPAND"],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_stack(cfn, bad_stack))
    bad_cs_status, bad_cs_reason = _poll(
        lambda: _change_set_outcome(cfn, bad_stack, bad_cs),
        lambda sr: sr[0] not in ("CREATE_PENDING", "CREATE_IN_PROGRESS"),
        budget_s=120.0, what="rejected change set settled",
    )
    assert bad_cs_status == "FAILED", (
        f"a MaxAge of 86401 must fail early validation; change set ended {bad_cs_status!r}: "
        f"{bad_cs_reason!r}"
    )
    errors = _validation_errors(cfn, bad_stack, bad_cs)
    assert len(errors) == 1, f"expected exactly one early-validation error; got {errors!r}"
    error = errors[0]
    assert (error["LogicalResourceId"], error["ResourceType"]) == ("FnUrl", "AWS::Lambda::Url"), (
        f"the validation error must point at the generated FnUrl Url resource; got {error!r}"
    )
    assert error["ValidationStatusReason"] == "#/Cors/MaxAge: 86401 is not less or equal to 86400", (
        f"the early-validation message must name the offending value and the 86400 ceiling; "
        f"got {error['ValidationStatusReason']!r}"
    )

    try:
        gone = lam.get_function(FunctionName=bad_fn)
    except ClientError as exc:
        err = (exc.response["Error"]["Code"], exc.response["Error"].get("Message"))
        assert err == (
            "ResourceNotFoundException",
            f"Function not found: arn:aws:lambda:{ctx.region}:{ctx.account}:function:{bad_fn}",
        ), f"GetFunction for the rejected deploy must name the function's own ARN; got {err!r}"
    else:
        raise AssertionError(f"function {bad_fn!r} exists despite the rejected deploy: {gone!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
