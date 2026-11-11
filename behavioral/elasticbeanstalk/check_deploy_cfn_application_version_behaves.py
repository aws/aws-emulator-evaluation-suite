"""deploy-cfn-application-version-behaves."""
from __future__ import annotations

import io
import json
import time
import urllib.error
import urllib.request
import zipfile

from botocore.exceptions import WaiterError

from behavioral_harness import tags


def _routed_request(ctx, url, data=None, headers=None, **kwargs):
    """A urllib Request that reaches ``url`` on the target, with ``ctx.endpoint_route``'s headers."""
    target, route = ctx.endpoint_route(url)
    return urllib.request.Request(target, data=data, headers={**(headers or {}), **route}, **kwargs)


CHECK = "deploy-cfn-application-version-behaves"
GROUP = "deploy"
SERVICES = ["elasticbeanstalk"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """An AWS::ElasticBeanstalk::ApplicationVersion deployed via CloudFormation serves: the environment is Ready
    on that version label, and an HTTP request to its CNAME returns the marker baked into the source bundle."""
    eb = ctx.client("elasticbeanstalk")
    s3 = ctx.client("s3")
    cfn = ctx.client("cloudformation")

    stack_name = ctx.unique_name("sim2real-eb-cfn-av-")
    app_name = ctx.unique_name("sim2real-eb-cfn-av-app-")
    env_name = _short_env_name(ctx, "ebcfa")
    cname_prefix = _short_env_name(ctx, "ebcfac").lower()
    marker = ctx.unique_name("marker-")

    stack_platform = _pick_solution_stack(ctx, needs="Node.js")

    bucket = eb.create_storage_location()["S3Bucket"]
    key = f"{app_name}/bundle.zip"
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("package.json", json.dumps({"name": "sim2real-app", "version": "1.0.0", "scripts": {"start": "node app.js"}}))
        zf.writestr(
            "app.js",
            "const http=require('http');"
            f"http.createServer((req,res)=>{{res.end('{marker}');}}).listen(process.env.PORT||8080);",
        )
        zf.writestr("Procfile", "web: node app.js\n")
    buf.seek(0)
    s3.put_object(Bucket=bucket, Key=key, Body=buf.getvalue())
    ctx.on_cleanup(lambda: s3.delete_object(Bucket=bucket, Key=key))

    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "App": {"Type": "AWS::ElasticBeanstalk::Application", "Properties": {"ApplicationName": app_name}},
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
                    "EnvironmentName": env_name,
                    "CNAMEPrefix": cname_prefix,
                    "SolutionStackName": stack_platform,
                    "VersionLabel": {"Ref": "AppVersion"},
                    "OptionSettings": [
                        {"Namespace": "aws:autoscaling:launchconfiguration", "OptionName": "IamInstanceProfile", "Value": {"Ref": "InstanceProfile"}},
                        {"Namespace": "aws:elasticbeanstalk:environment", "OptionName": "ServiceRole", "Value": {"Ref": "ServiceRole"}},
                        {"Namespace": "aws:elasticbeanstalk:environment", "OptionName": "EnvironmentType", "Value": "SingleInstance"},
                    ],
                },
            },
        },
    }

    cfn.create_stack(StackName=stack_name, TemplateBody=json.dumps(template), Capabilities=["CAPABILITY_IAM"])
    # the stack owns Application+ApplicationVersion+Environment; deleting it tears all three
    # down, so no separate elasticbeanstalk cleanup call is registered
    ctx.on_cleanup(lambda: cfn.delete_stack(StackName=stack_name))

    waiter = cfn.get_waiter("stack_create_complete")
    try:
        waiter.wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 1200})
    except WaiterError:
        pass
    stack_status = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
    if stack_status != "CREATE_COMPLETE":
        reason = _stack_failure_reason(cfn, stack_name)
        raise AssertionError(f"stack ended in {stack_status}, not CREATE_COMPLETE: {reason}")

    resources = cfn.describe_stack_resources(StackName=stack_name)["StackResources"]
    app_version_physical_id = next(
        r["PhysicalResourceId"] for r in resources if r["LogicalResourceId"] == "AppVersion"
    )

    env = _wait_env_status(ctx, env_name, {"Ready", "Terminated"}, timeout_s=900.0)
    assert env["Status"] == "Ready", f"CloudFormation reported CREATE_COMPLETE but environment is {env['Status']!r}"
    assert env["VersionLabel"] == app_version_physical_id, (
        f"environment reports VersionLabel={env['VersionLabel']!r}, expected the deployed "
        f"ApplicationVersion's label {app_version_physical_id!r}"
    )

    body = _poll_http_body(ctx, f"http://{env['CNAME']}/", timeout_s=300.0, interval_s=15.0)
    assert body == marker, f"HTTP response body was {body!r}, expected the version's baked-in marker {marker!r}"


def _short_env_name(ctx, tag: str) -> str:
    raw = ctx.unique_name("x")
    suffix = "".join(c for c in raw if c.isalnum())[-10:]
    return f"{tag}-{suffix}"[:40]


def _pick_solution_stack(ctx, needs: str = "Node.js") -> str:
    eb = ctx.client("elasticbeanstalk")
    stacks = eb.list_available_solution_stacks()["SolutionStacks"]
    for s in stacks:
        if "Amazon Linux 2" in s and needs in s:
            return s
    return stacks[0]


def _wait_env_status(ctx, env_name: str, targets, timeout_s: float = 1200.0, interval_s: float = 20.0):
    eb = ctx.client("elasticbeanstalk")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        resp = eb.describe_environments(EnvironmentNames=[env_name], IncludeDeleted=False)
        envs = resp.get("Environments", [])
        if envs:
            last = envs[0]
            if last["Status"] in targets:
                return last
        time.sleep(interval_s)
    raise AssertionError(f"environment {env_name} did not reach {targets} within {timeout_s}s (last={last})")


def _stack_failure_reason(cfn, stack_name: str) -> str:
    try:
        events = cfn.describe_stack_events(StackName=stack_name)["StackEvents"]
    except Exception as e:
        return f"<could not fetch events: {e}>"
    reasons = []
    for e in events:
        if e.get("ResourceStatus", "").endswith("FAILED") and e.get("ResourceStatusReason"):
            reasons.append(f"{e.get('LogicalResourceId')}: {e['ResourceStatusReason']}")
    return " | ".join(reasons[:5]) if reasons else "<no failure reason found in events>"


def _poll_http_body(ctx, url: str, *, timeout_s: float, interval_s: float) -> str:
    deadline = time.monotonic() + timeout_s
    last_error = None
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(_routed_request(ctx, url), timeout=10) as resp:
                return resp.read().decode("utf-8", errors="replace")
        except (urllib.error.URLError, OSError) as e:
            last_error = e
            time.sleep(interval_s)
    raise AssertionError(f"never got a successful HTTP response from {url} within {timeout_s}s (last error: {last_error})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
