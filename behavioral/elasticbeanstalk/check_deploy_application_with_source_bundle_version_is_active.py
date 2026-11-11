"""deploy-application-with-source-bundle-version-is-active."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "deploy-application-with-source-bundle-version-is-active"
GROUP = "deploy"
SERVICES = ["elasticbeanstalk"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "plane:control")
def run(ctx: Any) -> None:
    """A CloudFormation stack that deploys an app version from a real S3
    source bundle must leave the environment actually RUNNING that version
    (not just the stack reaching CREATE_COMPLETE) and healthy."""
    eb = ctx.client("elasticbeanstalk")
    s3 = ctx.client("s3")
    cfn = ctx.client("cloudformation")

    app_name = ctx.unique_name("sim2real-eb5-app-")
    stack_name = ctx.unique_name("sim2real-eb5-stack-")
    solution_stack = _pick_solution_stack(ctx)

    bucket = eb.create_storage_location()["S3Bucket"]
    key = f"{app_name}/bundle.zip"
    s3.put_object(Bucket=bucket, Key=key, Body=_sample_nodejs_bundle())
    ctx.on_cleanup(lambda: s3.delete_object(Bucket=bucket, Key=key))

    template = {
        "Resources": {
            "App": {
                "Type": "AWS::ElasticBeanstalk::Application",
                "Properties": {"ApplicationName": app_name},
            },
            "AppVersion": {
                "Type": "AWS::ElasticBeanstalk::ApplicationVersion",
                "Properties": {
                    "ApplicationName": {"Ref": "App"},
                    "SourceBundle": {"S3Bucket": bucket, "S3Key": key},
                },
            },
            "ServiceRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {"Effect": "Allow", "Principal": {"Service": "elasticbeanstalk.amazonaws.com"}, "Action": "sts:AssumeRole"}
                        ],
                    },
                    "ManagedPolicyArns": [
                        "arn:aws:iam::aws:policy/service-role/AWSElasticBeanstalkEnhancedHealth",
                        "arn:aws:iam::aws:policy/AWSElasticBeanstalkManagedUpdatesCustomerRolePolicy",
                    ],
                },
            },
            "InstanceRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}],
                    },
                    "ManagedPolicyArns": ["arn:aws:iam::aws:policy/AWSElasticBeanstalkWebTier"],
                },
            },
            "InstanceProfile": {
                "Type": "AWS::IAM::InstanceProfile",
                "Properties": {"Roles": [{"Ref": "InstanceRole"}]},
            },
            "Env": {
                "Type": "AWS::ElasticBeanstalk::Environment",
                "Properties": {
                    "ApplicationName": {"Ref": "App"},
                    "VersionLabel": {"Ref": "AppVersion"},
                    "SolutionStackName": solution_stack,
                    "OptionSettings": [
                        {"Namespace": "aws:elasticbeanstalk:environment", "OptionName": "EnvironmentType", "Value": "SingleInstance"},
                        {"Namespace": "aws:elasticbeanstalk:environment", "OptionName": "ServiceRole", "Value": {"Ref": "ServiceRole"}},
                        {"Namespace": "aws:autoscaling:launchconfiguration", "OptionName": "IamInstanceProfile", "Value": {"Ref": "InstanceProfile"}},
                        {"Namespace": "aws:elasticbeanstalk:healthreporting:system", "OptionName": "SystemType", "Value": "enhanced"},
                    ],
                },
            },
        }
    }

    status = _deploy_cfn(ctx, stack_name, template, timeout_s=900.0, capabilities=["CAPABILITY_IAM"])
    if status != "CREATE_COMPLETE":
        events = cfn.describe_stack_events(StackName=stack_name)["StackEvents"]
        reasons = [
            f"{e['LogicalResourceId']}[{e['ResourceStatus']}]: {e.get('ResourceStatusReason', '')}"
            for e in events
            if e["ResourceStatus"].endswith("FAILED")
        ]
        raise AssertionError(f"stack {stack_name} ended in {status!r}, not CREATE_COMPLETE: {reasons}")
    ctx.on_cleanup(lambda: eb.delete_application(ApplicationName=app_name, TerminateEnvByForce=True))

    versions = eb.describe_application_versions(ApplicationName=app_name)["ApplicationVersions"]
    assert len(versions) == 1, f"expected exactly one application version for {app_name}, found {len(versions)}"
    deployed_label = versions[0]["VersionLabel"]
    assert deployed_label != "Sample Application", (
        "deployed version label is the EB default sample app, not the version this check created "
        f"from its own S3 source bundle (bucket={bucket!r}, key={key!r})"
    )

    envs = eb.describe_environments(ApplicationName=app_name, IncludeDeleted=False)["Environments"]
    assert len(envs) == 1, f"expected exactly one environment for {app_name}, found {len(envs)}"
    env_name = envs[0]["EnvironmentName"]
    assert envs[0]["VersionLabel"] == deployed_label, (
        f"environment {env_name} reports VersionLabel={envs[0]['VersionLabel']!r}, "
        f"expected the deployed version {deployed_label!r}"
    )

    health = _wait_until(
        lambda: eb.describe_environment_health(EnvironmentName=env_name, AttributeNames=["All"]),
        lambda h: h.get("Status") == "Ready" and h.get("HealthStatus") in ("Ok", "Info"),
        timeout_s=600.0,
        interval_s=20.0,
    )
    assert health["Status"] == "Ready", f"environment {env_name} health Status={health.get('Status')!r}, expected Ready"
    assert health["HealthStatus"] in ("Ok", "Info"), (
        f"environment {env_name} HealthStatus={health.get('HealthStatus')!r}, expected Ok or Info"
    )

    final_env = eb.describe_environments(EnvironmentNames=[env_name])["Environments"][0]
    assert final_env["VersionLabel"] == deployed_label, (
        f"after health settled, environment {env_name} reports VersionLabel="
        f"{final_env['VersionLabel']!r}, expected it to still be running {deployed_label!r}"
    )


def _sample_nodejs_bundle() -> bytes:
    package_json = json.dumps({"name": "sim2real-eb-app", "version": "1.0.0", "scripts": {"start": "node app.js"}})
    app_js = (
        "const http = require('http');\n"
        "const port = process.env.PORT || 8080;\n"
        "http.createServer((req, res) => { res.writeHead(200); res.end('OK'); }).listen(port);\n"
    )
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("package.json", package_json)
        zf.writestr("app.js", app_js)
    return buf.getvalue()


def _pick_solution_stack(ctx) -> str:
    eb = ctx.client("elasticbeanstalk")
    stacks = eb.list_available_solution_stacks()["SolutionStacks"]
    matches = [s for s in stacks if "Node.js" in s and "Docker" not in s]
    if not matches:
        raise AssertionError("no Node.js (non-Docker) solution stack available in this region")
    return matches[0]


def _wait_until(probe, predicate, timeout_s: float, interval_s: float = 15.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out after {timeout_s}s; last observed={last!r}")


def _deploy_cfn(
    ctx,
    stack_name: str,
    template: dict,
    timeout_s: float = 900.0,
    on_failure: str | None = None,
    capabilities: list[str] | None = None,
) -> str:
    cfn = ctx.client("cloudformation")
    kwargs: dict[str, Any] = {
        "StackName": stack_name,
        "TemplateBody": json.dumps(template),
        "Tags": [{"Key": "sim2real", "Value": CHECK}],
    }
    if on_failure:
        kwargs["OnFailure"] = on_failure
    if capabilities:
        kwargs["Capabilities"] = capabilities

    def _cleanup():
        try:
            cfn.delete_stack(StackName=stack_name)
            _wait_stack_terminal(cfn, stack_name, {"DELETE_COMPLETE"}, timeout_s=timeout_s, allow_missing=True)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "StackNotFoundException":
                raise

    cfn.create_stack(**kwargs)
    ctx.on_cleanup(_cleanup)
    return _wait_stack_terminal(
        cfn, stack_name, {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED"}, timeout_s=timeout_s
    )


def _wait_stack_terminal(cfn, stack_name: str, terminal_statuses: set, timeout_s: float, allow_missing: bool = False) -> str:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            stacks = cfn.describe_stacks(StackName=stack_name)["Stacks"]
        except Exception:
            if allow_missing:
                return "DELETE_COMPLETE"
            raise
        if not stacks:
            if allow_missing:
                return "DELETE_COMPLETE"
        else:
            last = stacks[0]["StackStatus"]
            if last in terminal_statuses:
                return last
        time.sleep(2)
    raise AssertionError(f"stack {stack_name} did not reach a terminal status within {timeout_s}s; last={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
