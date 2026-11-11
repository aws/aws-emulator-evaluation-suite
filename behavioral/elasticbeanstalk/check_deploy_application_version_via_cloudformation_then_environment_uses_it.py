"""deploy-application-version-via-cloudformation-then-environment-uses-it."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "deploy-application-version-via-cloudformation-then-environment-uses-it"
GROUP = "deploy"
SERVICES = ["elasticbeanstalk"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:representation", "plane:control")
def run(ctx: Any) -> None:
    """A CloudFormation-deployed AWS::ElasticBeanstalk::ApplicationVersion is actually attached
    to its target environment: DescribeEnvironments reports the matching VersionLabel."""
    eb = ctx.client("elasticbeanstalk")
    cfn = ctx.client("cloudformation")
    s3 = ctx.client("s3")

    app_name = ctx.unique_name("sim2real-eb-app-")
    env_name = ctx.unique_name("sim2real-eb-env-")
    stack_name = ctx.unique_name("sim2real-eb-stack-")
    stack_ns = _pick_solution_stack(ctx)

    bucket = eb.create_storage_location()["S3Bucket"]
    key = f"{stack_name}/app.zip"
    s3.put_object(
        Bucket=bucket,
        Key=key,
        Body=_build_minimal_app_bundle(),
        Tagging="sim2real=elasticbeanstalk-behavioral",
    )
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
                    "EnvironmentName": env_name,
                    "VersionLabel": {"Ref": "AppVersion"},
                    "SolutionStackName": stack_ns,
                    "OptionSettings": [
                        {"Namespace": "aws:elasticbeanstalk:environment", "OptionName": "EnvironmentType", "Value": "SingleInstance"},
                        {"Namespace": "aws:autoscaling:launchconfiguration", "OptionName": "InstanceType", "Value": "t3.micro"},
                        {"Namespace": "aws:autoscaling:launchconfiguration", "OptionName": "IamInstanceProfile", "Value": {"Ref": "InstanceProfile"}},
                    ],
                    "Tags": [{"Key": "sim2real", "Value": "elasticbeanstalk-behavioral"}],
                },
            },
        }
    }

    _deploy_cfn(ctx, stack_name, template, timeout_s=1500, env_name=env_name)

    version_label = cfn.describe_stack_resource(StackName=stack_name, LogicalResourceId="AppVersion")[
        "StackResourceDetail"
    ]["PhysicalResourceId"]

    envs = eb.describe_environments(EnvironmentNames=[env_name], IncludeDeleted=False)["Environments"]
    assert len(envs) == 1, f"expected exactly one environment named {env_name}, found {len(envs)}"
    assert envs[0]["VersionLabel"] == version_label, (
        f"environment VersionLabel {envs[0]['VersionLabel']!r} does not match deployed "
        f"ApplicationVersion physical id {version_label!r}"
    )


def _build_minimal_app_bundle() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(
            "package.json",
            '{"name": "sim2real-app", "version": "1.0.0", "scripts": {"start": "node app.js"}}\n',
        )
        zf.writestr(
            "app.js",
            "const http = require('http');\n"
            "http.createServer((req, res) => { res.end('ok'); })\n"
            "  .listen(process.env.PORT || 8080);\n",
        )
    return buf.getvalue()


def _pick_solution_stack(ctx: Any) -> str:
    eb = ctx.client("elasticbeanstalk")
    stacks = eb.list_available_solution_stacks()["SolutionStacks"]
    if not stacks:
        raise AssertionError("account/region has no available Elastic Beanstalk solution stacks")
    for s in stacks:
        if "Amazon Linux 2" in s and "Node.js" in s:
            return s
    return stacks[0]


def _deploy_cfn(
    ctx: Any, stack_name: str, template: dict[str, Any], timeout_s: float = 900.0, env_name: str | None = None
) -> None:
    cfn = ctx.client("cloudformation")

    def _cleanup() -> None:
        cfn.delete_stack(StackName=stack_name)
        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline:
            try:
                resp = cfn.describe_stacks(StackName=stack_name)
            except ClientError as exc:
                err = exc.response["Error"]
                if err["Code"] != "StackNotFoundException" and not (
                    err["Code"] == "ValidationError" and "does not exist" in err.get("Message", "")
                ):
                    raise
                return
            stacks = resp.get("Stacks", [])
            if not stacks or stacks[0]["StackStatus"] == "DELETE_COMPLETE":
                return
            time.sleep(15)

    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=json.dumps(template),
        OnFailure="DELETE",
        Capabilities=["CAPABILITY_IAM"],
    )
    ctx.on_cleanup(_cleanup)

    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        resp = cfn.describe_stacks(StackName=stack_name)
        status = resp["Stacks"][0]["StackStatus"]
        if status == "CREATE_COMPLETE":
            return
        if status in ("CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_IN_PROGRESS", "DELETE_IN_PROGRESS"):
            reason = resp["Stacks"][0].get("StackStatusReason", "<no reason>")
            events = cfn.describe_stack_events(StackName=stack_name)["StackEvents"]
            failed = [
                f"{e['LogicalResourceId']}: {e.get('ResourceStatusReason', '<no reason>')}"
                for e in events
                if e["ResourceStatus"].endswith("_FAILED")
            ]
            eb_events = "<not fetched>"
            if env_name is not None:
                eb = ctx.client("elasticbeanstalk")
                try:
                    eb_events = [
                        f"{e['Severity']}: {e['Message']}"
                        for e in eb.describe_events(EnvironmentName=env_name, MaxRecords=10)["Events"]
                    ]
                except Exception as exc:
                    eb_events = f"<describe_events failed: {exc}>"
            raise AssertionError(
                f"stack {stack_name} entered failure status {status!r}: {reason}; "
                f"failed resources: {failed}; eb events: {eb_events}"
            )
        time.sleep(2)
    raise AssertionError(f"stack {stack_name} never reached CREATE_COMPLETE, last status {status!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
