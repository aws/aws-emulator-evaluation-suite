"""deploy-parameter-via-cloudformation-then-overwrite-behaves."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "deploy-parameter-via-cloudformation-then-overwrite-behaves"
GROUP = "state-machine"
SERVICES = ["ssm"]


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:deploy", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A CloudFormation-deployed AWS::SSM::Parameter returns its templated value, an Overwrite put
    moves it to Version 2, and deleting the stack makes GetParameter fail ParameterNotFound."""
    ssm = ctx.client("ssm")
    cfn = ctx.client("cloudformation")
    param_name = ctx.unique_name("sim2real-cfn-param-")
    stack_name = ctx.unique_name("sim2real-ssm-cfn-")
    template = json.dumps(
        {
            "Resources": {
                "Param": {
                    "Type": "AWS::SSM::Parameter",
                    "Properties": {
                        "Name": param_name,
                        "Type": "String",
                        "Value": "cfn-templated-value",
                    },
                }
            }
        }
    )

    cfn.create_stack(StackName=stack_name, TemplateBody=template)
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_name))
    cfn.get_waiter("stack_create_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 300}
    )

    got = ssm.get_parameter(Name=param_name)["Parameter"]
    assert got["Value"] == "cfn-templated-value", f"expected templated value, got {got['Value']!r}"
    assert got["Version"] == 1, f"expected initial Version 1, got {got['Version']}"

    put = ssm.put_parameter(
        Name=param_name, Value="overwritten-value-2", Type="String", Overwrite=True
    )
    assert put["Version"] == 2, f"expected Version 2 after overwrite, got {put['Version']}"

    got2 = ssm.get_parameter(Name=param_name)["Parameter"]
    assert got2["Value"] == "overwritten-value-2", (
        f"expected overwritten value, got {got2['Value']!r}"
    )
    assert got2["Version"] == 2, f"expected Version 2 on independent read, got {got2['Version']}"

    _delete_stack(cfn, stack_name)
    code, message = _error(lambda: ssm.get_parameter(Name=param_name))
    assert code == "ParameterNotFound", f"expected ParameterNotFound after stack delete, got {code}"
    # AWS sends ParameterNotFound with an empty message.
    assert message == "", message


def _delete_stack(cfn, stack_name: str) -> None:
    cfn.delete_stack(StackName=stack_name)
    cfn.get_waiter("stack_delete_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 300}
    )


def _error(fn):
    """Call fn(); return its error (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message", "")
    raise AssertionError(f"expected ClientError, call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
