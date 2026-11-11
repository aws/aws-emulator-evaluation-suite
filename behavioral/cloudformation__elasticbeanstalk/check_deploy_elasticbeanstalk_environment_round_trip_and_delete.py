"""deploy-elasticbeanstalk-environment-round-trip-and-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-elasticbeanstalk-environment-round-trip-and-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "elasticbeanstalk"]

# ---- CloudFormation helpers ----

_TERMINAL = frozenset({
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "DELETE_COMPLETE", "DELETE_FAILED", "UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE",
    "UPDATE_FAILED", "UPDATE_ROLLBACK_FAILED", "IMPORT_COMPLETE", "IMPORT_ROLLBACK_COMPLETE",
    "IMPORT_ROLLBACK_FAILED",
})
_DELETE_BUDGET_S = 600.0  # per stack; at most two stacks fit the suites' 1800 s cleanup budget


def paginate(client, op, key, **kw):
    """Every item under ``key`` across all pages of ``op``; presence and absence read every page.

    A ``key`` the operation's output does not declare fails instead of reading as [].
    """
    model = client.meta.service_model.operation_model(client.meta.method_to_api_mapping[op])
    assert key in model.output_shape.members, f"{op} output has no member {key!r}"
    return [x for page in client.get_paginator(op).paginate(**kw) for x in page.get(key, [])]


def wait_stack(cf, stack_id, terminal=_TERMINAL, timeout_s=300.0):
    """Poll DescribeStacks by StackId every 2 s until a status in ``terminal``; return it.

    Every error propagates: no ClientError ever stands for "done" or "gone".
    """
    deadline = time.monotonic() + timeout_s
    while True:
        status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if status in terminal:
            return status
        if time.monotonic() > deadline:
            raise AssertionError(f"stack {stack_id} still {status!r} after {timeout_s:.0f}s")
        time.sleep(2)


def delete_stack(cf, stack_id):
    """Delete by StackId within one deadline; raise unless DELETE_COMPLETE. Safe to call twice.

    A stack still creating or updating is first waited out; a failure names each resource's reason.
    """
    deadline = time.monotonic() + _DELETE_BUDGET_S
    status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
    if status == "DELETE_COMPLETE":
        return
    if status.endswith("_IN_PROGRESS") and status not in ("DELETE_IN_PROGRESS",
                                                          "REVIEW_IN_PROGRESS"):
        wait_stack(cf, stack_id, _TERMINAL, deadline - time.monotonic())
    cf.delete_stack(StackName=stack_id)
    status = wait_stack(cf, stack_id, {"DELETE_COMPLETE", "DELETE_FAILED"},
                        deadline - time.monotonic())
    if status != "DELETE_COMPLETE":
        events = stack_events(cf, stack_id)
        starts = [i for i, e in enumerate(events) if e.get("PhysicalResourceId") == stack_id
                  and e["ResourceStatus"] == "DELETE_IN_PROGRESS"]
        failed = [(e["LogicalResourceId"], e.get("ResourceStatusReason"))
                  for e in events[starts[-1] if starts else 0:]
                  if e["ResourceStatus"] == "DELETE_FAILED"]
        raise AssertionError(f"stack {stack_id} delete ended {status!r}: {failed!r}")


def delete_stack_named(cf, name, stack_id=None):
    """delete_stack by ``stack_id``, else by the StackId DescribeStacks(StackName=name) returns.

    A ``name`` CloudFormation never accepted ("does not exist") is nothing to delete; the
    client's own ``ClientError`` keeps the helper free of imports.
    """
    if stack_id is None:
        try:
            stack_id = cf.describe_stacks(StackName=name)["Stacks"][0]["StackId"]
        except cf.exceptions.ClientError as exc:
            err = exc.response["Error"]
            if (err.get("Code"), err.get("Message")) == (
                    "ValidationError", f"Stack with id {name} does not exist"):
                return
            raise
    delete_stack(cf, stack_id)


def create_stack(ctx, cf, name, template, **kw):
    """CreateStack tagged sim2real=<name> (propagates to every taggable resource); cleanup first.

    ``name`` comes from ctx.unique_name("sim2real-..."), so the tag value is unique per run. The
    cleanup is registered before the call: a stack AWS accepted is deleted even if the call raises.
    """
    created = {}
    ctx.on_cleanup(lambda: delete_stack_named(cf, name, created.get("StackId")))
    created["StackId"] = cf.create_stack(
        StackName=name, TemplateBody=template, Tags=[{"Key": "sim2real", "Value": name}], **kw
    )["StackId"]
    return created["StackId"]


def stack_outputs(cf, stack_id):
    """The stack's Outputs as {OutputKey: OutputValue}."""
    stack = cf.describe_stacks(StackName=stack_id)["Stacks"][0]
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}


def stack_events(cf, stack_id):
    """Every DescribeStackEvents row of the stack, oldest first."""
    return paginate(cf, "describe_stack_events", "StackEvents", StackName=stack_id)[::-1]


def decisive_rows(events, *logical_ids):
    """``(logical id, status)`` of each non-IN_PROGRESS row, oldest first (subsequence asserts)."""
    return [
        (e["LogicalResourceId"], e["ResourceStatus"]) for e in events
        if not e["ResourceStatus"].endswith("_IN_PROGRESS")
        and (not logical_ids or e["LogicalResourceId"] in logical_ids)
    ]


_VPC_CIDR = "10.60.0.0/16"
_SUBNET_CIDR = "10.60.1.0/24"
_INSTANCE_TYPE = "t3.micro"


def _template(app_name: str, env_name: str, solution_stack: str) -> str:
    """A VPC whose instance SG admits nothing, an instance profile, an Application and Environment.

    The environment's default EC2 security group (port 80 open to the internet) is disabled, so
    the single instance reaches Elastic Beanstalk outbound but accepts no inbound traffic. A
    SingleInstance environment always gets an Elastic IP and a public elasticbeanstalk.com CNAME;
    with no inbound rule, nothing behind either is reachable.
    """
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Vpc": {"Type": "AWS::EC2::VPC", "Properties": {
                "CidrBlock": _VPC_CIDR, "EnableDnsSupport": True, "EnableDnsHostnames": True}},
            "Igw": {"Type": "AWS::EC2::InternetGateway"},
            "Attach": {"Type": "AWS::EC2::VPCGatewayAttachment", "Properties": {
                "VpcId": {"Ref": "Vpc"}, "InternetGatewayId": {"Ref": "Igw"}}},
            "Subnet": {"Type": "AWS::EC2::Subnet", "Properties": {
                "VpcId": {"Ref": "Vpc"}, "CidrBlock": _SUBNET_CIDR,
                "AvailabilityZone": {"Fn::Select": [0, {"Fn::GetAZs": ""}]}}},
            "RouteTable": {"Type": "AWS::EC2::RouteTable", "Properties": {"VpcId": {"Ref": "Vpc"}}},
            "Route": {"Type": "AWS::EC2::Route", "DependsOn": "Attach", "Properties": {
                "RouteTableId": {"Ref": "RouteTable"}, "DestinationCidrBlock": "0.0.0.0/0",
                "GatewayId": {"Ref": "Igw"}}},
            "SubnetRouteTableAssociation": {"Type": "AWS::EC2::SubnetRouteTableAssociation",
                "Properties": {"SubnetId": {"Ref": "Subnet"}, "RouteTableId": {"Ref": "RouteTable"}}},
            "InstanceSg": {"Type": "AWS::EC2::SecurityGroup", "Properties": {
                "GroupDescription": "sim2real eb instance, no ingress", "VpcId": {"Ref": "Vpc"}}},
            "InstanceRole": {"Type": "AWS::IAM::Role", "Properties": {
                "AssumeRolePolicyDocument": {"Version": "2012-10-17", "Statement": [{
                    "Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"},
                    "Action": "sts:AssumeRole"}]},
                "ManagedPolicyArns": [{"Fn::Sub":
                    "arn:${AWS::Partition}:iam::aws:policy/AWSElasticBeanstalkWebTier"}],
            }},
            "InstanceProfile": {"Type": "AWS::IAM::InstanceProfile", "Properties": {
                "Roles": [{"Ref": "InstanceRole"}]}},
            "Application": {"Type": "AWS::ElasticBeanstalk::Application", "Properties": {
                "ApplicationName": app_name}},
            "Environment": {"Type": "AWS::ElasticBeanstalk::Environment", "Properties": {
                "ApplicationName": {"Ref": "Application"},
                "EnvironmentName": env_name,
                "SolutionStackName": solution_stack,
                "OptionSettings": [
                    {"Namespace": ns, "OptionName": name, "Value": value}
                    for ns, name, value in _options()
                ],
            }},
        },
        "Outputs": {
            "EnvironmentName": {"Value": {"Ref": "Environment"}},
            "ApplicationName": {"Value": {"Ref": "Application"}},
            "EndpointURL": {"Value": {"Fn::GetAtt": ["Environment", "EndpointURL"]}},
            "VpcId": {"Value": {"Ref": "Vpc"}},
            "SubnetId": {"Value": {"Ref": "Subnet"}},
            "InstanceSgId": {"Value": {"Ref": "InstanceSg"}},
            "InstanceProfileName": {"Value": {"Ref": "InstanceProfile"}},
        },
    })


def _options():
    """``(namespace, option, value)`` of every OptionSetting the template sets."""
    lc = "aws:autoscaling:launchconfiguration"
    return [
        ("aws:elasticbeanstalk:environment", "EnvironmentType", "SingleInstance"),
        (lc, "IamInstanceProfile", {"Ref": "InstanceProfile"}),
        (lc, "InstanceType", _INSTANCE_TYPE),
        (lc, "DisableDefaultEC2SecurityGroup", "true"),
        (lc, "SecurityGroups", {"Ref": "InstanceSg"}),
        ("aws:ec2:vpc", "VPCId", {"Ref": "Vpc"}),
        ("aws:ec2:vpc", "Subnets", {"Ref": "Subnet"}),
        ("aws:ec2:vpc", "AssociatePublicIpAddress", "true"),
    ]


def _solution_stack(eb) -> str:
    stacks = eb.list_available_solution_stacks()["SolutionStacks"]
    python_stacks = [s for s in stacks if "running Python" in s]
    assert python_stacks, f"no Python solution stack available in this account/region, got {stacks!r}"
    return python_stacks[0]


def _delete_environment_keys(s3, bucket: str, env_ids: list[str]) -> None:
    """Delete exactly the storage-bucket keys Elastic Beanstalk wrote for this run's environment.

    The bucket is an account-wide singleton other runs share, so only keys under the
    environment's own id (its resources and its logs) are removed, never the bucket.
    """
    for env_id in env_ids:
        keys = []
        for prefix in (f"resources/environments/{env_id}/", "resources/environments/logs/"):
            try:
                listed = paginate(s3, "list_objects_v2", "Contents", Bucket=bucket, Prefix=prefix)
            except ClientError as exc:
                if exc.response["Error"]["Code"] == "NoSuchBucket":
                    return
                raise
            keys += [o["Key"] for o in listed if env_id in o["Key"].split("/")]
        for start in range(0, len(keys), 1000):
            batch = [{"Key": k} for k in keys[start:start + 1000]]
            errors = s3.delete_objects(Bucket=bucket, Delete={"Objects": batch}).get("Errors", [])
            assert not errors, f"failed to delete {errors!r} from {bucket!r}"


def _env_status(eb, env_name: str, target: str, timeout_s: float) -> dict:
    """DescribeEnvironments (deleted included) polled (bounded) to the documented ``target``."""
    deadline = time.monotonic() + timeout_s
    while True:
        envs = eb.describe_environments(EnvironmentNames=[env_name],
                                        IncludeDeleted=True)["Environments"]
        assert envs, f"describe_environments({env_name!r}) returned nothing"
        if envs[0]["Status"] == target:
            return envs[0]
        if time.monotonic() > deadline:
            raise AssertionError(f"environment {env_name!r} still {envs[0]['Status']!r}")
        time.sleep(5)


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:representation",
      "plane:control")
def run(ctx) -> None:
    """A CloudFormation Elastic Beanstalk Environment's settings and Application read back.

    Ref names the application's one environment, with its solution stack and option settings;
    deleting the stack leaves the 'Terminated' tombstone and removes the application.
    """
    cfn = ctx.client("cloudformation")
    eb = ctx.client("elasticbeanstalk")
    s3 = ctx.client("s3")
    app_name = ctx.unique_name("sim2real-ebapp-")
    env_name = ctx.unique_name("s2r-ebe-")[:40]
    solution_stack = _solution_stack(eb)
    env_ids: list[str] = []
    bucket = f"elasticbeanstalk-{ctx.region}-{ctx.account}"
    # Elastic Beanstalk keeps one storage bucket per account and region, shared by every environment;
    # the check removes only the keys its own environments write and leaves the shared bucket in place.
    ctx.on_cleanup(lambda: _delete_environment_keys(s3, bucket, env_ids))

    stack_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-ebenv-"),
                            _template(app_name, env_name, solution_stack),
                            Capabilities=["CAPABILITY_IAM"])
    status = wait_stack(cfn, stack_id, timeout_s=1800.0)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    out = stack_outputs(cfn, stack_id)
    got = (out["ApplicationName"], out["EnvironmentName"])
    assert got == (app_name, env_name), f"Refs {got!r}, expected {(app_name, env_name)!r}"

    # Ref against an independent read: the environments the application lists.
    envs = eb.describe_environments(ApplicationName=app_name)["Environments"]
    assert [e["EnvironmentName"] for e in envs] == [env_name], f"environments of {app_name!r}: {envs!r}"
    env = envs[0]
    env_ids.append(env["EnvironmentId"])
    got = (env["Status"], env["SolutionStackName"], env["EndpointURL"])
    assert got == ("Ready", solution_stack, out["EndpointURL"]), f"environment reads {got!r}"
    apps = eb.describe_applications(ApplicationNames=[app_name])["Applications"]
    assert [a["ApplicationName"] for a in apps] == [app_name], f"applications {apps!r}"

    settings = eb.describe_configuration_settings(ApplicationName=app_name,
                                                  EnvironmentName=env_name)["ConfigurationSettings"]
    assert len(settings) == 1, f"describe_configuration_settings returned {settings!r}"
    options = {(o["Namespace"], o["OptionName"]): o.get("Value")
               for o in settings[0]["OptionSettings"]}
    refs = {"InstanceProfile": out["InstanceProfileName"], "InstanceSg": out["InstanceSgId"],
            "Vpc": out["VpcId"], "Subnet": out["SubnetId"]}
    want = {(ns, name): refs[v["Ref"]] if isinstance(v, dict) else v for ns, name, v in _options()}
    got = {key: options.get(key) for key in want}
    assert got == want, f"option settings {got!r}, expected {want!r}"

    delete_stack(cfn, stack_id)
    terminated = _env_status(eb, env_name, "Terminated", timeout_s=120)
    assert terminated["EnvironmentId"] == env["EnvironmentId"], f"tombstone {terminated!r}"
    apps = eb.describe_applications(ApplicationNames=[app_name])["Applications"]
    assert apps == [], f"the deleted application still lists: {apps!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
