"""appconfig-application-cloudformation-behaves."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "appconfig-application-cloudformation-behaves"
GROUP = "deploy"
SERVICES = ["appconfig"]

_TEMPLATE = """
AWSTemplateFormatVersion: '2010-09-09'
Parameters:
  AppName:
    Type: String
Resources:
  App:
    Type: AWS::AppConfig::Application
    Properties:
      Name: !Ref AppName
      Description: sim2real behavioral cfn check
      Tags:
        - Key: sim2real:managed
          Value: "true"
  Env:
    Type: AWS::AppConfig::Environment
    Properties:
      ApplicationId: !Ref App
      Name: !Sub "${AppName}-env"
      Tags:
        - Key: sim2real:managed
          Value: "true"
  Profile:
    Type: AWS::AppConfig::ConfigurationProfile
    Properties:
      ApplicationId: !Ref App
      Name: !Sub "${AppName}-profile"
      LocationUri: hosted
      Tags:
        - Key: sim2real:managed
          Value: "true"
Outputs:
  ApplicationId:
    Value: !Ref App
  EnvironmentId:
    Value: !Ref Env
  ConfigurationProfileId:
    Value: !Ref Profile
"""


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation stack of an AppConfig Application, Environment and ConfigurationProfile
    reaches CREATE_COMPLETE, and each resource is readable and listed through the AppConfig API
    with the template's names (the environment ReadyForDeployment)."""
    cfn = ctx.client("cloudformation")
    appconfig = ctx.client("appconfig")

    app_name = ctx.unique_name("sim2real-behav-cfnapp-")
    stack_name = ctx.unique_name("sim2real-behav-stack-")

    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=_TEMPLATE,
        Parameters=[{"ParameterKey": "AppName", "ParameterValue": app_name}],
    )
    ctx.on_cleanup(lambda: _delete_stack(ctx, stack_name))

    status = _poll_stack_status(ctx, stack_name, timeout_s=180.0)
    assert status == "CREATE_COMPLETE", f"stack ended in unexpected status {status}"

    outputs = {
        o["OutputKey"]: o["OutputValue"]
        for o in cfn.describe_stacks(StackName=stack_name)["Stacks"][0].get("Outputs", [])
    }
    app_id = outputs["ApplicationId"]
    env_id = outputs["EnvironmentId"]
    profile_id = outputs["ConfigurationProfileId"]

    # each of the three CFN-provisioned resource types must independently exist
    # and be correct through control-plane reads distinct from create_stack --
    # not just the stack's own template echo.
    got = appconfig.get_application(ApplicationId=app_id)
    assert got["Name"] == app_name, f"expected application name {app_name!r}, got {got['Name']!r}"

    listed_ids = {
        item["Id"]
        for page in appconfig.get_paginator("list_applications").paginate()
        for item in page["Items"]
    }
    assert app_id in listed_ids, f"application {app_id} missing from ListApplications"

    got_env = appconfig.get_environment(ApplicationId=app_id, EnvironmentId=env_id)
    assert got_env["Name"] == f"{app_name}-env", (
        f"expected environment name {app_name}-env, got {got_env['Name']!r}"
    )
    assert got_env["State"] == "ReadyForDeployment", (
        f"expected freshly-created environment State ReadyForDeployment, got {got_env['State']!r}"
    )
    listed_env_ids = {item["Id"] for item in appconfig.list_environments(ApplicationId=app_id)["Items"]}
    assert env_id in listed_env_ids, f"environment {env_id} missing from ListEnvironments"

    got_profile = appconfig.get_configuration_profile(ApplicationId=app_id, ConfigurationProfileId=profile_id)
    assert got_profile["Name"] == f"{app_name}-profile", (
        f"expected configuration profile name {app_name}-profile, got {got_profile['Name']!r}"
    )
    assert got_profile["LocationUri"] == "hosted", (
        f"expected LocationUri hosted, got {got_profile['LocationUri']!r}"
    )
    listed_profile_ids = {
        item["Id"] for item in appconfig.list_configuration_profiles(ApplicationId=app_id)["Items"]
    }
    assert profile_id in listed_profile_ids, f"configuration profile {profile_id} missing from ListConfigurationProfiles"



def _poll_stack_status(ctx, stack_name: str, *, timeout_s: float = 180.0, interval_s: float = 5.0) -> str:
    cfn = ctx.client("cloudformation")
    terminal = {
        "CREATE_COMPLETE",
        "CREATE_FAILED",
        "ROLLBACK_COMPLETE",
        "ROLLBACK_FAILED",
    }
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        if status in terminal:
            return status
        time.sleep(interval_s)
    return status


def _delete_stack(ctx, stack_name: str) -> None:
    cfn = ctx.client("cloudformation")
    try:
        cfn.delete_stack(StackName=stack_name)
        deadline = time.monotonic() + 180.0
        while time.monotonic() < deadline:
            try:
                stacks = cfn.describe_stacks(StackName=stack_name)["Stacks"]
            except ClientError as exc:
                if exc.response["Error"]["Code"] not in (
                    "StackNotFoundException",
                    "ValidationError",
                ):
                    raise
                return
            if not stacks or stacks[0]["StackStatus"] == "DELETE_COMPLETE":
                return
            time.sleep(5.0)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("StackNotFoundException", "ValidationError"):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
