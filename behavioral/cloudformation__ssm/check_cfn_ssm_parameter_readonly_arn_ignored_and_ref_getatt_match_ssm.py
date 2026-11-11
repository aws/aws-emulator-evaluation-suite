"""cfn-ssm-parameter-readonly-arn-ignored-and-ref-getatt-match-ssm."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-ssm-parameter-readonly-arn-ignored-and-ref-getatt-match-ssm"
GROUP = "deploy"
SERVICES = ["cloudformation", "ssm"]

_VALUE = "sim2real-cfnro-ssm-value"

_STACK_TERMINAL = {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
                   "DELETE_COMPLETE", "DELETE_FAILED"}


def _wait_stack(cfn, stack_id: str, *, timeout_s: float = 240.0, interval_s: float = 2.0) -> str:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if last in _STACK_TERMINAL:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"stack {stack_id!r} not terminal within {timeout_s}s (last={last!r})")


def _delete_stack_and_wait(cfn, stack_id: str) -> None:
    cfn.delete_stack(StackName=stack_id)
    status = _wait_stack(cfn, stack_id)
    if status != "DELETE_COMPLETE":
        raise AssertionError(f"stack {stack_id!r} delete ended {status!r}")


def _outputs(cfn, stack_id: str) -> dict:
    return {o["OutputKey"]: o["OutputValue"]
            for o in cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["Outputs"]}


def _error(fn) -> dict:
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _template(param_name: str, bogus_arn: str) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Param": {
                "Type": "AWS::SSM::Parameter",
                "Properties": {
                    "Name": param_name,
                    "Type": "String",
                    "Value": _VALUE,
                    "Tags": {"sim2real": CHECK},
                    # This type's only readOnlyProperty, set to a value AWS never minted.
                    "Arn": bogus_arn,
                },
            },
        },
        "Outputs": {
            "ParamRef": {"Value": {"Ref": "Param"}},
            "ParamArnAttr": {"Value": {"Fn::GetAtt": ["Param", "Arn"]}},
        },
    })


@tags(
    "axis:happy-path", "cap:c1", "concern:deploy", "concern:representation", "plane:control",
)
def run(ctx) -> None:
    """A template that sets AWS::SSM::Parameter's readOnlyProperty Arn deploys as if it were
    absent: Ref is the name, Fn::GetAtt Arn is SSM's documented ARN, Type, Value and Tags read
    back from SSM, and the stack delete leaves ParameterNotFound."""
    cfn = ctx.client("cloudformation")
    ssm = ctx.client("ssm")

    param_name = ctx.unique_name("sim2real-behav-cfnro-ssm-")
    stack_name = ctx.unique_name("sim2real-behav-cfnro-ssm-stk-")
    bogus_arn = f"arn:aws:ssm:{ctx.region}:111122223333:parameter/not-the-real-parameter"

    stack_id = cfn.create_stack(
        StackName=stack_name,
        TemplateBody=_template(param_name, bogus_arn),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["StackId"]
    ctx.on_cleanup(lambda: _delete_stack_and_wait(cfn, stack_id))

    status = _wait_stack(cfn, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"a readOnlyProperty value in the template must not block the create; got {status!r}")

    real = ssm.get_parameter(Name=param_name)["Parameter"]
    expected_arn = f"arn:aws:ssm:{ctx.region}:{ctx.account}:parameter/{param_name}"
    assert real["ARN"] == expected_arn, (
        f"SSM's ARN is not the documented parameter ARN of {param_name!r}: {real['ARN']!r}")
    assert (real["Type"], real["Value"]) == ("String", _VALUE), (
        f"Type/Value read back from SSM as {(real['Type'], real['Value'])!r}")
    tag_list = ssm.list_tags_for_resource(
        ResourceType="Parameter", ResourceId=param_name)["TagList"]
    own_tags = {t["Key"]: t["Value"] for t in tag_list if not t["Key"].startswith("aws:")}
    assert own_tags == {"sim2real": CHECK}, f"the parameter's Tags read back as {own_tags!r}"

    outputs = _outputs(cfn, stack_id)
    assert outputs["ParamRef"] == real["Name"] == param_name, (
        f"Ref must equal SSM's own Name {real['Name']!r}; got {outputs['ParamRef']!r}")
    assert outputs["ParamArnAttr"] == expected_arn, (
        f"GetAtt Arn must equal SSM's own ARN {real['ARN']!r}; got {outputs['ParamArnAttr']!r}")

    _delete_stack_and_wait(cfn, stack_id)
    err = _error(lambda: ssm.get_parameter(Name=param_name))
    assert (err["Code"], err["Message"]) == ("ParameterNotFound", ""), (
        f"reading the deleted parameter returned {(err['Code'], err['Message'])!r}, "
        f"expected ParameterNotFound with SSM's empty message")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
