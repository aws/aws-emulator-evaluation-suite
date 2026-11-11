"""deploy-ssm-parameter-via-cloudformation-then-behaves."""
from __future__ import annotations

import json
from typing import Any

from behavioral_harness import tags

CHECK = "deploy-ssm-parameter-via-cloudformation-then-behaves"
GROUP = "deploy"
SERVICES = ["ssm"]

_TEMPLATE = {
    "AWSTemplateFormatVersion": "2010-09-09",
    "Parameters": {"ParamName": {"Type": "String"}},
    "Resources": {
        "Param": {
            "Type": "AWS::SSM::Parameter",
            "Properties": {
                "Name": {"Ref": "ParamName"},
                "Type": "String",
                "Value": "v1-initial",
                "Tier": "Standard",
            },
        }
    },
}


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:deploy", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A CFN-managed SSM parameter round-trips GetParameter/PutParameter version bumps,
    and an Overwrite=False re-create of the same name is rejected without mutating it."""
    cfn = ctx.client("cloudformation")
    ssm = ctx.client("ssm")
    stack_name = ctx.unique_name("sim2real-ssmparam-stack-")
    param_name = ctx.unique_name("sim2real-ssmparam-")

    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=json.dumps(_TEMPLATE),
        Parameters=[{"ParameterKey": "ParamName", "ParameterValue": param_name}],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_name))
    cfn.get_waiter("stack_create_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 300}
    )
    status = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
    assert status == "CREATE_COMPLETE", f"expected CREATE_COMPLETE, got {status}"

    got = ssm.get_parameter(Name=param_name)["Parameter"]
    assert got["Value"] == "v1-initial", f"expected the CFN-templated value, got {got['Value']!r}"
    assert got["Type"] == "String", f"expected type String, got {got['Type']!r}"
    assert got["Version"] == 1, f"expected the CFN-created parameter to start at version 1, got {got['Version']}"

    put_resp = ssm.put_parameter(Name=param_name, Value="v2-updated", Type="String", Overwrite=True)
    assert put_resp["Version"] == 2, f"expected overwrite to bump version to 2, got {put_resp['Version']}"

    got2 = ssm.get_parameter(Name=param_name)["Parameter"]
    assert got2["Value"] == "v2-updated", f"expected v2-updated, got {got2['Value']!r}"
    assert got2["Version"] == 2, f"expected version 2, got {got2['Version']}"

    # Negative: attempting to (re)create the same name without Overwrite is rejected,
    # and the parameter's current value/version is left untouched by the failed attempt.
    code, message = _error(
        lambda: ssm.put_parameter(Name=param_name, Value="should-not-apply", Type="String")
    )
    assert code == "ParameterAlreadyExists", f"expected ParameterAlreadyExists, got {code!r}"
    assert message == (
        "The parameter already exists. To overwrite this value, set the overwrite option "
        "in the request to true."
    ), message
    got3 = ssm.get_parameter(Name=param_name)["Parameter"]
    assert got3["Value"] == "v2-updated", f"rejected put must not mutate the value, got {got3['Value']!r}"
    assert got3["Version"] == 2, f"rejected put must not bump the version, got {got3['Version']}"

    # Teardown is asserted, not just performed: deleting the CFN stack must delete the
    # SSM parameter it owns, independently observable via GetParameter's own not-found code.
    _delete_stack(cfn, stack_name)
    code2, message2 = _error(lambda: ssm.get_parameter(Name=param_name))
    assert code2 == "ParameterNotFound", f"expected ParameterNotFound after stack teardown, got {code2!r}"
    # AWS sends ParameterNotFound with an empty message.
    assert message2 == "", message2


# ===== helpers =====
def _error(fn: Any):
    """Call fn(); return its error (code, message). An unexpected SUCCESS raises, so an over-permissive
    target fails as an acceptance, not as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message", "")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _delete_stack(cfn, stack_name: str) -> None:
    # DeleteStack on a deleted stack is a no-op and the waiter counts "does not exist" as done.
    cfn.delete_stack(StackName=stack_name)
    cfn.get_waiter("stack_delete_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 300}
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
