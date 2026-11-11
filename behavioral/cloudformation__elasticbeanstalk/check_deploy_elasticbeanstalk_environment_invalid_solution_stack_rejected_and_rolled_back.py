"""deploy-elasticbeanstalk-environment-invalid-solution-stack-rejected-and-rolled-back."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-elasticbeanstalk-environment-invalid-solution-stack-rejected-and-rolled-back"
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
_HANDLER_REASON = re.compile(
    r'^Resource handler returned message: "(?P<message>.*)" '
    r"\(RequestToken: [0-9a-f-]+, HandlerErrorCode: (?P<code>[A-Za-z]+)\)$",
    re.DOTALL,
)


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


def stack_events(cf, stack_id):
    """Every DescribeStackEvents row of the stack, oldest first."""
    return paginate(cf, "describe_stack_events", "StackEvents", StackName=stack_id)[::-1]


def failed_reason(events, logical_id, status="CREATE_FAILED"):
    """The reason on the single ``status`` row of ``logical_id``: never an *_IN_PROGRESS row."""
    rows = [e.get("ResourceStatusReason") for e in events
            if e["LogicalResourceId"] == logical_id and e["ResourceStatus"] == status]
    assert len(rows) == 1, f"expected one {status} row for {logical_id}, got {rows!r}"
    return rows[0]


def masked(text, account, *names):
    """``text`` masking only Request ID, RequestToken, SDK Attempt Count, account, run names."""
    text = re.sub(r"((?:Extended )?Request ID): [^,;)]+", r"\1: <id>", text)
    text = re.sub(r"RequestToken: [0-9a-f-]+", "RequestToken: <token>", text)
    text = re.sub(r"SDK Attempt Count: \d+", "SDK Attempt Count: <n>", text)
    text = text.replace(account, "<account>")
    for name in sorted(names, key=len, reverse=True):
        text = text.replace(name, "<name>")
    return text


def handler_reason(reason, account, *names):
    """``(masked message, HandlerErrorCode)`` of a registry-handler reason; compare with ==."""
    m = _HANDLER_REASON.match(reason or "")
    assert m is not None, f"not a resource-handler failure reason: {reason!r}"
    return masked(m["message"], account, *names), m["code"]


_VPC_CIDR = "10.61.0.0/16"
_SUBNET_CIDR = "10.61.1.0/24"
_BAD_SOLUTION_STACK = "sim2real-not-a-real-solution-stack"
_REJECTED = (
    f"No Solution Stack named '{_BAD_SOLUTION_STACK}' found. (Service: ElasticBeanstalk, "
    "Status Code: 400, Request ID: <id>) (SDK Attempt Count: <n>)",
    "InvalidRequest",
)
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


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:deploy", "concern:negative-classes",
      "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation Elastic Beanstalk Environment naming an unknown solution stack is refused.

    The handler relays Elastic Beanstalk's exact reason and the rollback leaves no application
    of that name, while the same template with a real solution stack deploys and reads back.
    """
    cfn = ctx.client("cloudformation")
    eb = ctx.client("elasticbeanstalk")
    s3 = ctx.client("s3")
    env_ids: list[str] = []
    bucket = f"elasticbeanstalk-{ctx.region}-{ctx.account}"
    # Elastic Beanstalk keeps one storage bucket per account and region, shared by every environment;
    # the check removes only the keys its own environments write and leaves the shared bucket in place.
    ctx.on_cleanup(lambda: _delete_environment_keys(s3, bucket, env_ids))

    bad_app = ctx.unique_name("sim2real-ebappbad-")
    bad_env = ctx.unique_name("s2r-ebbad-")[:40]
    bad_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-ebenvbad-"),
                          _template(bad_app, bad_env, _BAD_SOLUTION_STACK),
                          Capabilities=["CAPABILITY_IAM"])
    status = wait_stack(cfn, bad_id, timeout_s=600.0)
    assert status == "ROLLBACK_COMPLETE", f"rejected stack ended {status!r}"
    got = handler_reason(failed_reason(stack_events(cfn, bad_id), "Environment"), ctx.account,
                         bad_app, bad_env)
    assert got == _REJECTED, f"handler reason {got!r}, expected {_REJECTED!r}"
    # Rollback absence through Elastic Beanstalk, before this check's own delete.
    apps = eb.describe_applications(ApplicationNames=[bad_app])["Applications"]
    assert apps == [], f"the rolled-back application still lists: {apps!r}"
    envs = eb.describe_environments(EnvironmentNames=[bad_env])["Environments"]
    assert envs == [], f"an environment named {bad_env!r} exists: {envs!r}"
    delete_stack(cfn, bad_id)

    # Positive control: the same template (same CIDRs) with a real solution stack.
    solution_stack = _solution_stack(eb)
    good_app = ctx.unique_name("sim2real-ebappgood-")
    good_env = ctx.unique_name("s2r-ebgood-")[:40]
    good_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-ebenvgood-"),
                           _template(good_app, good_env, solution_stack),
                           Capabilities=["CAPABILITY_IAM"])
    status = wait_stack(cfn, good_id, timeout_s=1800.0)
    assert status == "CREATE_COMPLETE", f"the control stack ended {status!r}"
    envs = eb.describe_environments(ApplicationName=good_app)["Environments"]
    got = [(e["EnvironmentName"], e["Status"], e["SolutionStackName"]) for e in envs]
    assert got == [(good_env, "Ready", solution_stack)], f"control environments {got!r}"
    env_ids.append(envs[0]["EnvironmentId"])
    delete_stack(cfn, good_id)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
