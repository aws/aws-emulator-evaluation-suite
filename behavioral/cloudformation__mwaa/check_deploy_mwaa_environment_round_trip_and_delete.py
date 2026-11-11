"""deploy-mwaa-environment-round-trip-and-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-mwaa-environment-round-trip-and-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "mwaa"]

# ---- CloudFormation helpers: copy VERBATIM; delete the ones the check never calls. ----

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


def expect_error(fn, code, message, undo=None):
    """Assert ``fn()`` raises exactly ``(code, message)``.

    On an unexpected success ``undo(result)`` registers the cleanup before the failure is raised.
    """
    try:
        result = fn()
    except ClientError as exc:
        got = (exc.response["Error"].get("Code"), exc.response["Error"].get("Message"))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    if undo is not None:
        undo(result)
    raise AssertionError(f"expected {code} but the call succeeded: {result!r}")


# ---- Check-specific: the template, then run(). ----

_VPC_CIDR = "10.85.0.0/16"
_PRIVATE_CIDR_1 = "10.85.1.0/24"
_PRIVATE_CIDR_2 = "10.85.2.0/24"
# Private routing without internet access: the VPC endpoints Amazon MWAA documents for it.
_INTERFACE_ENDPOINTS = ("monitoring", "ecr.dkr", "ecr.api", "logs", "sqs", "kms", "airflow.api",
                        "airflow.env", "airflow.ops")
# An environment's stack delete has outlasted 1700 s; a pass took 4095 s for create + delete. The
# body shares one 5300 s deadline (the MWAA suite budget is 5400 s) between them, and the cleanup
# path's delete gets 3000 s (the MWAA cleanup budget is 3600 s).
_BODY_S = 5300.0
_TEARDOWN_S = 3000.0


def _trust_policy() -> dict:
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": ["airflow.amazonaws.com", "airflow-env.amazonaws.com"]},
                "Action": "sts:AssumeRole",
            }
        ],
    }


def _execution_policy(env_name: str) -> dict:
    """The execution role policy Amazon MWAA documents, scoped to this environment's resources."""
    bucket = {"Fn::GetAtt": ["Bucket", "Arn"]}
    return {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": "airflow:PublishMetrics", "Resource": {"Fn::Sub": (
                "arn:${AWS::Partition}:airflow:${AWS::Region}:${AWS::AccountId}:environment/"
                + env_name)}},
            {"Effect": "Allow", "Action": ["s3:GetObject*", "s3:GetBucket*", "s3:List*"],
             "Resource": [bucket, {"Fn::Sub": ["${Arn}/*", {"Arn": bucket}]}]},
            {
                "Effect": "Allow",
                "Action": [
                    "logs:CreateLogStream",
                    "logs:CreateLogGroup",
                    "logs:PutLogEvents",
                    "logs:GetLogEvents",
                    "logs:GetLogRecord",
                    "logs:GetLogGroupFields",
                    "logs:GetQueryResults",
                ],
                "Resource": {"Fn::Sub": (
                    "arn:${AWS::Partition}:logs:${AWS::Region}:${AWS::AccountId}:log-group:airflow-"
                    + env_name + "-*")},
            },
            {"Effect": "Allow", "Action": ["logs:DescribeLogGroups", "cloudwatch:PutMetricData"],
             "Resource": "*"},
            {
                "Effect": "Allow",
                "Action": [
                    "sqs:ChangeMessageVisibility",
                    "sqs:DeleteMessage",
                    "sqs:GetQueueAttributes",
                    "sqs:GetQueueUrl",
                    "sqs:ReceiveMessage",
                    "sqs:SendMessage",
                ],
                "Resource": {"Fn::Sub": "arn:${AWS::Partition}:sqs:${AWS::Region}:*:airflow-celery-*"},
            },
            {
                "Effect": "Allow",
                "Action": ["kms:Decrypt", "kms:DescribeKey", "kms:GenerateDataKey*", "kms:Encrypt"],
                "Resource": "*",
                "Condition": {"StringLike": {"kms:ViaService": [
                    {"Fn::Sub": "sqs.${AWS::Region}.amazonaws.com"}]}},
            },
        ],
    }


def _endpoint_id(service: str) -> str:
    """The logical id of the interface endpoint for ``service`` (e.g. ecr.dkr -> EcrDkrEndpoint)."""
    return "".join(part.capitalize() for part in service.split(".")) + "Endpoint"


def _template(env_name: str) -> str:
    """Two private subnets with no internet route; S3 through a gateway endpoint and every other
    service Amazon MWAA needs through an interface endpoint with private DNS."""
    t = [{"Key": "sim2real-env", "Value": env_name}]
    az1 = {"Fn::Select": [0, {"Fn::GetAZs": ""}]}
    az2 = {"Fn::Select": [1, {"Fn::GetAZs": ""}]}
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Vpc": {"Type": "AWS::EC2::VPC", "Properties": {
                "CidrBlock": _VPC_CIDR, "EnableDnsSupport": True, "EnableDnsHostnames": True,
                "Tags": t,
            }},
            "PrivateSubnet1": {"Type": "AWS::EC2::Subnet", "Properties": {
                "VpcId": {"Ref": "Vpc"}, "CidrBlock": _PRIVATE_CIDR_1, "AvailabilityZone": az1,
                "Tags": t,
            }},
            "PrivateSubnet2": {"Type": "AWS::EC2::Subnet", "Properties": {
                "VpcId": {"Ref": "Vpc"}, "CidrBlock": _PRIVATE_CIDR_2, "AvailabilityZone": az2,
                "Tags": t,
            }},
            "PrivateRouteTable": {"Type": "AWS::EC2::RouteTable", "Properties": {
                "VpcId": {"Ref": "Vpc"}, "Tags": t,
            }},
            "S3Endpoint": {"Type": "AWS::EC2::VPCEndpoint", "Properties": {
                "VpcId": {"Ref": "Vpc"}, "VpcEndpointType": "Gateway",
                "ServiceName": {"Fn::Sub": "com.amazonaws.${AWS::Region}.s3"},
                "RouteTableIds": [{"Ref": "PrivateRouteTable"}], "Tags": t,
            }},
            **{_endpoint_id(svc): {"Type": "AWS::EC2::VPCEndpoint", "Properties": {
                "VpcId": {"Ref": "Vpc"}, "VpcEndpointType": "Interface",
                "ServiceName": {"Fn::Sub": "com.amazonaws.${AWS::Region}." + svc},
                "SubnetIds": [{"Ref": "PrivateSubnet1"}, {"Ref": "PrivateSubnet2"}],
                "SecurityGroupIds": [{"Ref": "Sg"}], "PrivateDnsEnabled": True, "Tags": t,
            }} for svc in _INTERFACE_ENDPOINTS},
            "PrivateSubnet1RouteTableAssociation": {"Type": "AWS::EC2::SubnetRouteTableAssociation",
                "Properties": {"SubnetId": {"Ref": "PrivateSubnet1"}, "RouteTableId": {"Ref": "PrivateRouteTable"}}},
            "PrivateSubnet2RouteTableAssociation": {"Type": "AWS::EC2::SubnetRouteTableAssociation",
                "Properties": {"SubnetId": {"Ref": "PrivateSubnet2"}, "RouteTableId": {"Ref": "PrivateRouteTable"}}},
            "Sg": {"Type": "AWS::EC2::SecurityGroup", "Properties": {
                "VpcId": {"Ref": "Vpc"}, "GroupDescription": "sim2real mwaa provisioning check", "Tags": t,
            }},
            "SgSelfIngress": {"Type": "AWS::EC2::SecurityGroupIngress", "Properties": {
                "GroupId": {"Ref": "Sg"}, "IpProtocol": "-1", "SourceSecurityGroupId": {"Ref": "Sg"},
            }},
            "Bucket": {"Type": "AWS::S3::Bucket", "Properties": {
                "VersioningConfiguration": {"Status": "Enabled"}, "Tags": t,
            }},
            "ExecutionRole": {"Type": "AWS::IAM::Role", "Properties": {
                "AssumeRolePolicyDocument": _trust_policy(),
                "Policies": [{"PolicyName": "exec", "PolicyDocument": _execution_policy(env_name)}],
                "Tags": t,
            }},
            "MwaaEnvironment": {
                "Type": "AWS::MWAA::Environment",
                "DependsOn": [
                    "S3Endpoint", *map(_endpoint_id, _INTERFACE_ENDPOINTS),
                    "PrivateSubnet1RouteTableAssociation", "PrivateSubnet2RouteTableAssociation",
                    "SgSelfIngress",
                ],
                "Properties": {
                    "Name": env_name,
                    "ExecutionRoleArn": {"Fn::GetAtt": ["ExecutionRole", "Arn"]},
                    "SourceBucketArn": {"Fn::GetAtt": ["Bucket", "Arn"]},
                    "DagS3Path": "dags",
                    "NetworkConfiguration": {
                        "SubnetIds": [{"Ref": "PrivateSubnet1"}, {"Ref": "PrivateSubnet2"}],
                        "SecurityGroupIds": [{"Ref": "Sg"}],
                    },
                    "EnvironmentClass": "mw1.micro",
                    "MaxWorkers": 1,
                    "MinWorkers": 1,
                    "WebserverAccessMode": "PRIVATE_ONLY",
                    "Tags": {"sim2real-env": env_name},
                },
            },
        },
        "Outputs": {
            "EnvName": {"Value": {"Ref": "MwaaEnvironment"}},
            "EnvArn": {"Value": {"Fn::GetAtt": ["MwaaEnvironment", "Arn"]}},
            "CeleryQueue": {"Value": {"Fn::GetAtt": ["MwaaEnvironment", "CeleryExecutorQueue"]}},
            "DatabaseVpce": {"Value": {"Fn::GetAtt": ["MwaaEnvironment", "DatabaseVpcEndpointService"]}},
            "WebserverVpce": {"Value": {"Fn::GetAtt": ["MwaaEnvironment", "WebserverVpcEndpointService"]}},
            "WebserverUrl": {"Value": {"Fn::GetAtt": ["MwaaEnvironment", "WebserverUrl"]}},
            "RoleArn": {"Value": {"Fn::GetAtt": ["ExecutionRole", "Arn"]}},
            "BucketArn": {"Value": {"Fn::GetAtt": ["Bucket", "Arn"]}},
            "PrivateSubnet1Id": {"Value": {"Ref": "PrivateSubnet1"}},
            "PrivateSubnet2Id": {"Value": {"Ref": "PrivateSubnet2"}},
            "SgId": {"Value": {"Ref": "Sg"}},
        },
    })


def _delete_slow(cfn, stack_id: str, budget_s: float = _TEARDOWN_S) -> None:
    """delete_stack for an MWAA stack: wait out a create, delete, wait in one budget, then grade."""
    deadline = time.monotonic() + budget_s
    status = wait_stack(cfn, stack_id, timeout_s=budget_s)
    if status != "DELETE_COMPLETE":
        cfn.delete_stack(StackName=stack_id)
        wait_stack(cfn, stack_id, {"DELETE_COMPLETE", "DELETE_FAILED"},
                   deadline - time.monotonic())
    delete_stack(cfn, stack_id)


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:representation",
      "plane:control")
def run(ctx) -> None:
    """A CloudFormation AWS::MWAA::Environment reaches AVAILABLE in Amazon MWAA's GetEnvironment
    with the declared properties, tags and GetAtts, and deleting the stack leaves it unreadable
    (ResourceNotFoundException).

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-mwaa-environment.html
    """
    cfn = ctx.client("cloudformation")
    mwaa = ctx.client("mwaa")
    stack = ctx.unique_name("sim2real-mwaacfn-")
    env_name = ctx.unique_name("sim2real-mwaa-env-")

    stack_id = create_stack(ctx, cfn, stack, _template(env_name), Capabilities=["CAPABILITY_IAM"])
    ctx.on_cleanup(lambda: _delete_slow(cfn, stack_id))
    body_deadline = time.monotonic() + _BODY_S
    status = wait_stack(cfn, stack_id, timeout_s=4200.0)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    outputs = stack_outputs(cfn, stack_id)

    # Ref (the Name) against the paged ListEnvironments and the template input.
    listed = [n for n in paginate(mwaa, "list_environments", "Environments") if n == env_name]
    assert listed == [outputs["EnvName"]] == [env_name], (
        f"ListEnvironments {listed!r}, Ref {outputs['EnvName']!r}, declared {env_name!r}"
    )

    env = mwaa.get_environment(Name=listed[0])["Environment"]
    assert env["Name"] == env_name, f"GetEnvironment Name {env['Name']!r}"
    assert env["Status"] == "AVAILABLE", f"environment status is {env['Status']!r}"

    # Every GetAtt exported in Outputs equals Amazon MWAA's own value for the same attribute.
    got = {k: env.get(k) for k in ("Arn", "CeleryExecutorQueue", "DatabaseVpcEndpointService",
                                   "WebserverVpcEndpointService", "WebserverUrl")}
    want = {"Arn": outputs["EnvArn"], "CeleryExecutorQueue": outputs["CeleryQueue"],
            "DatabaseVpcEndpointService": outputs["DatabaseVpce"],
            "WebserverVpcEndpointService": outputs["WebserverVpce"],
            "WebserverUrl": outputs["WebserverUrl"]}
    assert got == want, f"GetAtts {want!r}, GetEnvironment {got!r}"

    # Every property the template set, and the tags, read back through Amazon MWAA.
    got = {k: env.get(k) for k in ("EnvironmentClass", "WebserverAccessMode", "DagS3Path",
                                   "ExecutionRoleArn", "SourceBucketArn", "MinWorkers",
                                   "MaxWorkers")}
    want = {"EnvironmentClass": "mw1.micro", "WebserverAccessMode": "PRIVATE_ONLY",
            "DagS3Path": "dags", "ExecutionRoleArn": outputs["RoleArn"],
            "SourceBucketArn": outputs["BucketArn"], "MinWorkers": 1, "MaxWorkers": 1}
    assert got == want, f"environment reads {got!r}, expected {want!r}"
    net = env["NetworkConfiguration"]
    got = (sorted(net["SubnetIds"]), net["SecurityGroupIds"])
    want = (sorted([outputs["PrivateSubnet1Id"], outputs["PrivateSubnet2Id"]]), [outputs["SgId"]])
    assert got == want, f"NetworkConfiguration {got!r}, expected {want!r}"
    env_tags = {k: v for k, v in env.get("Tags", {}).items() if not k.startswith("aws:")}
    assert env_tags == {"sim2real": stack, "sim2real-env": env_name}, f"tags {env_tags!r}"

    _delete_slow(cfn, stack_id, body_deadline - time.monotonic())
    not_found = ("ResourceNotFoundException", f"Environment {env_name} not found.")
    expect_error(lambda: mwaa.get_environment(Name=env_name), *not_found)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
