"""deploy-cfn-appconfig-deployment-strategy-and-deployment-reaches-complete."""

from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cfn-appconfig-deployment-strategy-and-deployment-reaches-complete"
GROUP = "deploy"
SERVICES = ["appconfig", "cloudformation"]

_TEMPLATE = """
AWSTemplateFormatVersion: "2010-09-09"
Parameters:
  AppName:
    Type: String
  EnvName:
    Type: String
  ProfileName:
    Type: String
  StrategyName:
    Type: String
Resources:
  App:
    Type: AWS::AppConfig::Application
    Properties:
      Name: !Ref AppName
  Env:
    Type: AWS::AppConfig::Environment
    Properties:
      ApplicationId: !Ref App
      Name: !Ref EnvName
  Profile:
    Type: AWS::AppConfig::ConfigurationProfile
    Properties:
      ApplicationId: !Ref App
      Name: !Ref ProfileName
      LocationUri: hosted
  HostedVersion:
    Type: AWS::AppConfig::HostedConfigurationVersion
    Properties:
      ApplicationId: !Ref App
      ConfigurationProfileId: !Ref Profile
      Content: '{"deploy_cfn_appconfig_fastest_strategy": "on"}'
      ContentType: application/json
  Strategy:
    Type: AWS::AppConfig::DeploymentStrategy
    Properties:
      Name: !Ref StrategyName
      DeploymentDurationInMinutes: 0
      GrowthFactor: 100
      FinalBakeTimeInMinutes: 0
      ReplicateTo: NONE
  Deployment:
    Type: AWS::AppConfig::Deployment
    DependsOn: HostedVersion
    Properties:
      ApplicationId: !Ref App
      EnvironmentId: !Ref Env
      ConfigurationProfileId: !Ref Profile
      DeploymentStrategyId: !Ref Strategy
      ConfigurationVersion: !GetAtt HostedVersion.VersionNumber
Outputs:
  AppId:
    Value: !Ref App
  EnvId:
    Value: !Ref Env
  StrategyId:
    Value: !Ref Strategy
  DeploymentNumber:
    Value: !GetAtt Deployment.DeploymentNumber
  DeploymentState:
    Value: !GetAtt Deployment.State
"""


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _wait_stack(ctx, cfn, stack_id: str, timeout_s: float, capped: bool = True) -> str:
    """Poll DescribeStacks by StackId every 2 s until the status leaves *_IN_PROGRESS; return it.
    ``capped`` bounds the deadline by the run budget; a wait the budget ended is not graded."""
    if capped:
        timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    while True:
        status = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if not status.endswith("_IN_PROGRESS"):
            return status
        if time.monotonic() > deadline:
            if capped and _budget_spent(ctx):
                raise TimeoutError(
                    f"stack {stack_id} reaching a terminal status: the run budget ended first; "
                    f"not graded"
                )
            raise AssertionError(f"stack {stack_id} still {status!r} after {timeout_s:.0f}s")
        time.sleep(2)


def _delete_stack(ctx, cfn, stack_id: str, capped: bool = True) -> None:
    """Delete by StackId from any terminal status; raise unless it reaches DELETE_COMPLETE."""
    status = _wait_stack(ctx, cfn, stack_id, 600.0, capped)
    if status == "DELETE_COMPLETE":
        return
    cfn.delete_stack(StackName=stack_id)
    status = _wait_stack(ctx, cfn, stack_id, 600.0, capped)
    if status != "DELETE_COMPLETE":
        raise AssertionError(f"stack {stack_id} delete ended {status!r}")


def _wait_deployment(ctx, appconfig, app_id: str, env_id: str, number: int) -> dict:
    """Poll GetDeployment every 2 s until State is COMPLETE; return the response."""
    timeout_s = _budget_s(ctx, 300.0)
    deadline = time.monotonic() + timeout_s
    while True:
        deployment = appconfig.get_deployment(
            ApplicationId=app_id, EnvironmentId=env_id, DeploymentNumber=number
        )
        if deployment["State"] == "COMPLETE":
            return deployment
        if time.monotonic() > deadline:
            if _budget_spent(ctx):
                raise TimeoutError(
                    f"deployment {number} reaching COMPLETE: the run budget ended first; not graded"
                )
            raise AssertionError(
                f"deployment {number} still {deployment['State']!r} after {timeout_s:.0f}s"
            )
        time.sleep(2)


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """An AWS::AppConfig::DeploymentStrategy at the fastest duration, growth and bake time drives
    an AWS::AppConfig::Deployment of a hosted configuration to State COMPLETE at 100%, and stack
    deletion leaves the strategy and the application not found."""
    cfn = ctx.client("cloudformation")
    appconfig = ctx.client("appconfig")

    app_name = ctx.unique_name("sim2real-behav-cfnapp-")
    env_name = ctx.unique_name("sim2real-behav-cfnenv-")
    profile_name = ctx.unique_name("sim2real-behav-cfnprofile-")
    strategy_name = ctx.unique_name("sim2real-behav-cfnstrategy-")
    stack_name = ctx.unique_name("sim2real-behav-stack-")

    stack_id = cfn.create_stack(
        StackName=stack_name,
        TemplateBody=_TEMPLATE,
        Parameters=[
            {"ParameterKey": "AppName", "ParameterValue": app_name},
            {"ParameterKey": "EnvName", "ParameterValue": env_name},
            {"ParameterKey": "ProfileName", "ParameterValue": profile_name},
            {"ParameterKey": "StrategyName", "ParameterValue": strategy_name},
        ],
    )["StackId"]
    ctx.on_cleanup(lambda: _delete_stack(ctx, cfn, stack_id, capped=False))

    status = _wait_stack(ctx, cfn, stack_id, 300.0)
    assert status == "CREATE_COMPLETE", f"expected stack status CREATE_COMPLETE, got {status!r}"
    stack = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack["Outputs"]}
    app_id = outputs["AppId"]
    env_id = outputs["EnvId"]
    strategy_id = outputs["StrategyId"]
    deployment_number = int(outputs["DeploymentNumber"])

    strategy = appconfig.get_deployment_strategy(DeploymentStrategyId=strategy_id)
    assert strategy["Name"] == strategy_name, (
        f"expected deployment strategy Name {strategy_name!r}, got {strategy['Name']!r}"
    )
    assert strategy["DeploymentDurationInMinutes"] == 0, (
        f"expected DeploymentDurationInMinutes 0, got {strategy['DeploymentDurationInMinutes']!r}"
    )
    assert strategy["GrowthFactor"] == 100, (
        f"expected GrowthFactor 100, got {strategy['GrowthFactor']!r}"
    )
    assert strategy["FinalBakeTimeInMinutes"] == 0, (
        f"expected FinalBakeTimeInMinutes 0, got {strategy['FinalBakeTimeInMinutes']!r}"
    )
    assert strategy["ReplicateTo"] == "NONE", (
        f"expected ReplicateTo NONE, got {strategy['ReplicateTo']!r}"
    )

    deployment = _wait_deployment(ctx, appconfig, app_id, env_id, deployment_number)
    assert deployment["PercentageComplete"] == 100, (
        f"expected PercentageComplete 100, got {deployment['PercentageComplete']!r}"
    )
    assert deployment["DeploymentStrategyId"] == strategy_id, (
        f"expected deployment DeploymentStrategyId {strategy_id!r}, got {deployment['DeploymentStrategyId']!r}"
    )
    assert outputs["DeploymentState"] == "COMPLETE", (
        f"expected stack output DeploymentState COMPLETE, got {outputs['DeploymentState']!r}"
    )

    _delete_stack(ctx, cfn, stack_id)

    code, message = _error(
        lambda: appconfig.get_deployment_strategy(DeploymentStrategyId=strategy_id)
    )
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException reading the deployment strategy after its owning "
        f"stack was deleted, got {code!r}: {message!r}"
    )
    assert message == f"DeploymentStrategy with Id {strategy_id} could not be found.", (
        f"unexpected not-found message {message!r}"
    )

    code, message = _error(lambda: appconfig.get_application(ApplicationId=app_id))
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException reading the application after its owning "
        f"stack was deleted, got {code!r}: {message!r}"
    )
    assert (
        message == f"Application with Id {app_id} could not be found for account {ctx.account}."
    ), f"unexpected not-found message {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
