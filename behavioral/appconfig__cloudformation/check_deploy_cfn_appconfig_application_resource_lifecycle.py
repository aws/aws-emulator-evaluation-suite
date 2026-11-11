"""deploy-cfn-appconfig-application-resource-lifecycle."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cfn-appconfig-application-resource-lifecycle"
GROUP = "deploy"
SERVICES = ["appconfig", "cloudformation"]

_TEMPLATE = """
AWSTemplateFormatVersion: "2010-09-09"
Parameters:
  AppName:
    Type: String
Resources:
  App:
    Type: AWS::AppConfig::Application
    Properties:
      Name: !Ref AppName
      Description: sim2real cfn resource existence check
Outputs:
  AppRef:
    Value: !Ref App
  AppIdGetAtt:
    Value: !GetAtt App.ApplicationId
"""


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


@tags("axis:happy-path", "cap:c1", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation AWS::AppConfig::Application reaches CREATE_COMPLETE, GetApplication
    reflects its Name and Description and every Fn::GetAtt attribute, and deleting the
    stack removes the application (GetApplication then raises ResourceNotFoundException)."""
    cfn = ctx.client("cloudformation")
    appconfig = ctx.client("appconfig")

    app_name = ctx.unique_name("sim2real-behav-cfnapp-")
    description = "sim2real cfn resource existence check"
    stack_name = ctx.unique_name("sim2real-behav-stack-")

    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=_TEMPLATE,
        Parameters=[{"ParameterKey": "AppName", "ParameterValue": app_name}],
    )
    ctx.on_cleanup(lambda: _safe_delete_stack(cfn, stack_name))

    cfn.get_waiter("stack_create_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150}
    )

    outputs = {
        o["OutputKey"]: o["OutputValue"]
        for o in cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["Outputs"]
    }
    app_id = outputs["AppRef"]
    assert outputs["AppIdGetAtt"] == app_id, (
        f"expected Fn::GetAtt App.ApplicationId to match Ref {app_id!r}, got {outputs['AppIdGetAtt']!r}"
    )

    got = appconfig.get_application(ApplicationId=app_id)
    assert got["Name"] == app_name, f"expected application Name {app_name!r}, got {got['Name']!r}"
    assert got["Description"] == description, (
        f"expected application Description {description!r}, got {got['Description']!r}"
    )

    cfn.delete_stack(StackName=stack_name)
    cfn.get_waiter("stack_delete_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150}
    )

    code, message = _error(lambda: appconfig.get_application(ApplicationId=app_id))
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException reading the application after its owning "
        f"stack was deleted, got {code!r}: {message!r}"
    )
    assert message == f"Application with Id {app_id} could not be found for account {ctx.account}.", (
        f"unexpected not-found message {message!r}"
    )


def _safe_delete_stack(cfn, stack_name: str) -> None:
    try:
        cfn.delete_stack(StackName=stack_name)
        cfn.get_waiter("stack_delete_complete").wait(
            StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150}
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "StackNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
