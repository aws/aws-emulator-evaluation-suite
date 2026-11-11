"""deploy-appconfig-experiment-via-cloudformation."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "deploy-appconfig-experiment-via-cloudformation"
GROUP = "deploy"
SERVICES = ["appconfig"]

_TEMPLATE = {
    "AWSTemplateFormatVersion": "2010-09-09",
    "Parameters": {
        "AppName": {"Type": "String"},
        "EnvName": {"Type": "String"},
        "ProfileName": {"Type": "String"},
        "ExperimentName": {"Type": "String"},
    },
    "Resources": {
        "Application": {
            "Type": "AWS::AppConfig::Application",
            "Properties": {"Name": {"Ref": "AppName"}},
        },
        "Environment": {
            "Type": "AWS::AppConfig::Environment",
            "Properties": {"ApplicationId": {"Ref": "Application"}, "Name": {"Ref": "EnvName"}},
        },
        "ConfigurationProfile": {
            "Type": "AWS::AppConfig::ConfigurationProfile",
            "Properties": {
                "ApplicationId": {"Ref": "Application"},
                "Name": {"Ref": "ProfileName"},
                "LocationUri": "hosted",
                "Type": "AWS.AppConfig.FeatureFlags",
            },
        },
        "HostedConfigVersion": {
            "Type": "AWS::AppConfig::HostedConfigurationVersion",
            "Properties": {
                "ApplicationId": {"Ref": "Application"},
                "ConfigurationProfileId": {"Ref": "ConfigurationProfile"},
                "Content": json.dumps(
                    {
                        "flags": {"checkoutflag": {"name": "checkoutflag"}},
                        "values": {"checkoutflag": {"enabled": True}},
                        "version": "1",
                    }
                ),
                "ContentType": "application/json",
            },
        },
        "ExperimentDefinition": {
            "Type": "AWS::AppConfig::ExperimentDefinition",
            "DependsOn": "HostedConfigVersion",
            "Properties": {
                "ApplicationIdentifier": {"Ref": "Application"},
                "Name": {"Ref": "ExperimentName"},
                "ConfigurationProfileIdentifier": {"Ref": "ConfigurationProfile"},
                "EnvironmentIdentifier": {"Ref": "Environment"},
                "FlagKey": "checkoutflag",
                "AudienceRule": '(eq $country "US")',
                "Control": {"Weight": 50, "Enabled": False},
                "Treatments": [{"Weight": 50, "Enabled": True}],
            },
        },
    },
    "Outputs": {
        "ApplicationId": {"Value": {"Ref": "Application"}},
        "EnvironmentId": {"Value": {"Ref": "Environment"}},
        "ConfigurationProfileId": {"Value": {"Ref": "ConfigurationProfile"}},
        "ExperimentDefinitionId": {"Value": {"Fn::GetAtt": ["ExperimentDefinition", "Id"]}},
        "HostedConfigVersionNumber": {"Value": {"Fn::GetAtt": ["HostedConfigVersion", "VersionNumber"]}},
    },
}


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """A CloudFormation stack provisioning an Application + ExperimentDefinition
    yields a genuinely usable resource: beyond CREATE_COMPLETE, StartExperimentRun
    succeeds against it and the definition's status flips IDLE -> ACTIVE."""
    experiment_name = ctx.unique_name("sim2real-appcfg-cfn-exp-")
    outputs = _deploy_cfn(
        ctx,
        _TEMPLATE,
        parameters={
            "AppName": ctx.unique_name("sim2real-appcfg-cfn-app-"),
            "EnvName": ctx.unique_name("sim2real-appcfg-cfn-env-"),
            "ProfileName": ctx.unique_name("sim2real-appcfg-cfn-profile-"),
            "ExperimentName": experiment_name,
        },
    )

    appconfig = ctx.client("appconfig")
    app_id = outputs["ApplicationId"]
    env_id = outputs["EnvironmentId"]
    profile_id = outputs["ConfigurationProfileId"]
    exp_id = outputs["ExperimentDefinitionId"]
    version_number = outputs["HostedConfigVersionNumber"]

    initial = appconfig.get_experiment_definition(
        ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=exp_id
    )
    assert initial["Name"] == experiment_name
    assert initial["Status"] == "IDLE"

    # StartExperimentRun requires an existing deployment of the configuration
    # profile to the environment -- deploy the CFN-provisioned hosted config
    # version now via a zero-duration/zero-bake strategy.
    strategy_id = appconfig.create_deployment_strategy(
        Name=ctx.unique_name("sim2real-appcfg-cfn-strategy-"),
        DeploymentDurationInMinutes=0,
        GrowthFactor=100.0,
        ReplicateTo="NONE",
        FinalBakeTimeInMinutes=0,
    )["Id"]
    ctx.on_cleanup(lambda: appconfig.delete_deployment_strategy(DeploymentStrategyId=strategy_id))
    deployment_number = appconfig.start_deployment(
        ApplicationId=app_id,
        EnvironmentId=env_id,
        DeploymentStrategyId=strategy_id,
        ConfigurationProfileId=profile_id,
        ConfigurationVersion=str(version_number),
    )["DeploymentNumber"]
    _wait_for_deployment_complete(appconfig, app_id, env_id, deployment_number)

    run_resp = appconfig.start_experiment_run(
        ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=exp_id
    )
    run_number = run_resp["Run"]
    ctx.on_cleanup(
        lambda: _safe_stop_run(appconfig, app_id, exp_id, run_number)
    )
    assert run_resp["Status"] == "RUNNING"

    active = appconfig.get_experiment_definition(
        ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=exp_id
    )
    assert active["Status"] == "ACTIVE"


def _deploy_cfn(ctx, template: dict[str, Any], parameters: dict[str, str]) -> dict[str, str]:
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-appcfg-experiment-stack-")
    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=json.dumps(template),
        Parameters=[{"ParameterKey": k, "ParameterValue": v} for k, v in parameters.items()],
        OnFailure="DO_NOTHING",
    )
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_name))
    waiter = cfn.get_waiter("stack_create_complete")
    try:
        waiter.wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    except Exception as err:
        events = cfn.describe_stack_events(StackName=stack_name)["StackEvents"]
        details = [
            f"{e['LogicalResourceId']} ({e['ResourceType']}) {e['ResourceStatus']}: {e.get('ResourceStatusReason', '')}"
            for e in events
        ]
        raise AssertionError(f"stack {stack_name} failed to create: {details}") from err
    stacks = cfn.describe_stacks(StackName=stack_name)["Stacks"]
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stacks[0].get("Outputs", [])}
    return outputs


def _delete_stack(cfn, stack_name: str) -> None:
    cfn.delete_stack(StackName=stack_name)
    waiter = cfn.get_waiter("stack_delete_complete")
    waiter.wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 300})


def _safe_stop_run(appconfig, app_id: str, exp_id: str, run_number: int) -> None:
    from botocore.exceptions import ClientError

    try:
        appconfig.stop_experiment_run(
            ApplicationIdentifier=app_id, ExperimentDefinitionIdentifier=exp_id, Run=run_number
        )
    except ClientError as err:
        if err.response["Error"]["Code"] not in ("ResourceNotFoundException", "ConflictException"):
            raise


def _wait_for_deployment_complete(
    appconfig, app_id: str, env_id: str, deployment_number: int, *, timeout_s: float = 90.0, interval_s: float = 3.0
) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = appconfig.get_deployment(
            ApplicationId=app_id, EnvironmentId=env_id, DeploymentNumber=deployment_number
        )
        if last["State"] == "COMPLETE":
            return last
        if last["State"] in ("ROLLED_BACK", "REVERTED"):
            raise AssertionError(f"deployment entered terminal failure state: {last!r}")
        time.sleep(interval_s)
    raise AssertionError(f"deployment did not reach COMPLETE within {timeout_s}s (last={last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
