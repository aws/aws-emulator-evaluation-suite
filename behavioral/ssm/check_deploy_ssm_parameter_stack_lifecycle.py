"""deploy-ssm-parameter-stack-lifecycle."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-ssm-parameter-stack-lifecycle"
GROUP = "state-machine"
SERVICES = ["ssm"]

_TEMPLATE = """
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  Param:
    Type: AWS::SSM::Parameter
    Properties:
      Name: !Sub "${AWS::StackName}-param"
      Type: String
      Value: "sim2real-cfn-managed-value"
Outputs:
  ParamName:
    Value: !Ref Param
"""


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A CloudFormation-deployed AWS::SSM::Parameter returns its declared String value from GetParameter, and after
    stack deletion GetParameter and DeleteParameter fail with ParameterNotFound (empty message)."""
    cfn = ctx.client("cloudformation")
    ssm = ctx.client("ssm")
    stack_name = ctx.unique_name("sim2real-ssm-param-stack-")

    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=_TEMPLATE,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_stack_if_exists(cfn, stack_name))
    cfn.get_waiter("stack_create_complete").wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 1800})

    outputs = {
        o["OutputKey"]: o["OutputValue"]
        for o in cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["Outputs"]
    }
    param_name = outputs["ParamName"]

    parameter = ssm.get_parameter(Name=param_name)["Parameter"]
    assert parameter["Value"] == "sim2real-cfn-managed-value", (
        f"expected the CFN-templated value, got {parameter['Value']!r}"
    )
    assert parameter["Type"] == "String", f"expected type String, got {parameter['Type']!r}"

    cfn.delete_stack(StackName=stack_name)
    cfn.get_waiter("stack_delete_complete").wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 1800})

    code, message = _error(lambda: ssm.get_parameter(Name=param_name))
    assert code == "ParameterNotFound", (
        f"expected GetParameter on the stack-deleted parameter to 404 with "
        f"ParameterNotFound, got {code!r}"
    )
    # AWS sends ParameterNotFound with an empty message.
    assert message == "", message

    # A mutation on the deleted id must also fail, not silently no-op.
    delete_code, delete_message = _error(lambda: ssm.delete_parameter(Name=param_name))
    assert delete_code == "ParameterNotFound", (
        f"expected DeleteParameter on the already-gone parameter to fail with "
        f"ParameterNotFound, got {delete_code!r}"
    )
    assert delete_message == "", delete_message


def _delete_stack_if_exists(cfn, stack_name: str) -> None:
    try:
        cfn.delete_stack(StackName=stack_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "StackNotFoundException":
            raise


def _error(fn):
    """Call fn(); return its error (code, message). An unexpected SUCCESS raises, so an
    emulator that accepts what AWS refuses cannot read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message", "")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
