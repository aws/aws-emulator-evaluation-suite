"""deploy-appflow-connector-profile-redshift-serverless-round-trip-and-delete."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "deploy-appflow-connector-profile-redshift-serverless-round-trip-and-delete"
GROUP = "deploy"
SERVICES = ["appflow", "cloudformation"]

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


# ---- Check-specific: the template, then run(). ----

_DB_NAME = "sim2realdb"
_TAG_KEY = "sim2real-afcp"


def _usable_azs(ec2, count: int) -> list[str]:
    usable = sorted(z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"])
    assert len(usable) >= count, f"only {len(usable)} available AZ(s), need {count}: {usable!r}"
    return usable[:count]


def _template(azs: list[str], names: dict[str, str], cidr_prefix: str,
              data_api_role_arn=None) -> str:
    """A Redshift Serverless workgroup, its S3 and Data API roles and an AppFlow profile on it.

    ``data_api_role_arn`` None names the stack's own Data API role.
    """
    t = [{"Key": _TAG_KEY, "Value": names["profile"]}]
    s3_trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "redshift.amazonaws.com"},
                       "Action": "sts:AssumeRole"}],
    }
    dataapi_trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "appflow.amazonaws.com"},
                       "Action": "sts:AssumeRole"}],
    }
    s3_policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow",
                       "Action": ["s3:GetObject", "s3:ListBucket", "s3:PutObject"],
                       "Resource": [{"Fn::Sub": "arn:${AWS::Partition}:s3:::${Bucket}"},
                                    {"Fn::Sub": "arn:${AWS::Partition}:s3:::${Bucket}/*"}]}],
    }
    workgroup_arn = {"Fn::GetAtt": ["Workgroup", "Workgroup.WorkgroupArn"]}
    dataapi_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow",
             "Action": ["redshift-data:ExecuteStatement", "redshift-data:BatchExecuteStatement",
                        "redshift-serverless:GetCredentials"],
             "Resource": workgroup_arn},
            # Statement reads take a statement id and support no resource-level scoping.
            {"Effect": "Allow",
             "Action": ["redshift-data:GetStatementResult", "redshift-data:DescribeStatement"],
             "Resource": "*"},
        ],
    }
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Vpc": {"Type": "AWS::EC2::VPC",
                    "Properties": {"CidrBlock": f"{cidr_prefix}.0.0/16", "Tags": t}},
            "SubnetA": {"Type": "AWS::EC2::Subnet",
                        "Properties": {"VpcId": {"Ref": "Vpc"}, "CidrBlock": f"{cidr_prefix}.1.0/24",
                                       "AvailabilityZone": azs[0], "Tags": t}},
            "SubnetB": {"Type": "AWS::EC2::Subnet",
                        "Properties": {"VpcId": {"Ref": "Vpc"}, "CidrBlock": f"{cidr_prefix}.2.0/24",
                                       "AvailabilityZone": azs[1], "Tags": t}},
            "SubnetC": {"Type": "AWS::EC2::Subnet",
                        "Properties": {"VpcId": {"Ref": "Vpc"}, "CidrBlock": f"{cidr_prefix}.3.0/24",
                                       "AvailabilityZone": azs[2], "Tags": t}},
            "Bucket": {"Type": "AWS::S3::Bucket",
                       "Properties": {"BucketName": names["bucket"], "Tags": t}},
            "S3AccessRole": {"Type": "AWS::IAM::Role",
                             "Properties": {"AssumeRolePolicyDocument": s3_trust,
                                            "Policies": [{"PolicyName": "sim2real-s3access",
                                                          "PolicyDocument": s3_policy}],
                                            "Tags": t}},
            "DataApiRole": {"Type": "AWS::IAM::Role",
                            "Properties": {"AssumeRolePolicyDocument": dataapi_trust,
                                           "Policies": [{"PolicyName": "sim2real-dataapi",
                                                         "PolicyDocument": dataapi_policy}],
                                           "Tags": t}},
            "Namespace": {"Type": "AWS::RedshiftServerless::Namespace",
                          "Properties": {"NamespaceName": names["namespace"],
                                         "DbName": _DB_NAME, "Tags": t}},
            "Workgroup": {"Type": "AWS::RedshiftServerless::Workgroup",
                          "DependsOn": "Namespace",
                          "Properties": {"WorkgroupName": names["workgroup"],
                                         "NamespaceName": {"Ref": "Namespace"},
                                         "SubnetIds": [{"Ref": "SubnetA"}, {"Ref": "SubnetB"},
                                                       {"Ref": "SubnetC"}],
                                         "SecurityGroupIds": [
                                             {"Fn::GetAtt": ["Vpc", "DefaultSecurityGroup"]}],
                                         "BaseCapacity": 8, "PubliclyAccessible": False,
                                         "Tags": t}},
            "ConnectorProfile": {"Type": "AWS::AppFlow::ConnectorProfile",
                                 "DependsOn": "Workgroup",
                                 "Properties": {
                                     "ConnectorProfileName": names["profile"],
                                     "ConnectorType": "Redshift",
                                     "ConnectionMode": "Public",
                                     "ConnectorProfileConfig": {
                                         "ConnectorProfileProperties": {
                                             "Redshift": {
                                                 "BucketName": {"Ref": "Bucket"},
                                                 "RoleArn": {"Fn::GetAtt": ["S3AccessRole", "Arn"]},
                                                 "DataApiRoleArn": data_api_role_arn or {
                                                     "Fn::GetAtt": ["DataApiRole", "Arn"]},
                                                 "IsRedshiftServerless": True,
                                                 "WorkgroupName": names["workgroup"],
                                                 "DatabaseName": _DB_NAME,
                                             }
                                         }
                                     },
                                 }},
        },
        "Outputs": {
            "ConnectorProfileName": {"Value": {"Ref": "ConnectorProfile"}},
            "ConnectorProfileArn": {
                "Value": {"Fn::GetAtt": ["ConnectorProfile", "ConnectorProfileArn"]}},
            "CredentialsArn": {"Value": {"Fn::GetAtt": ["ConnectorProfile", "CredentialsArn"]}},
            "S3RoleArn": {"Value": {"Fn::GetAtt": ["S3AccessRole", "Arn"]}},
            "DataApiRoleArn": {"Value": {"Fn::GetAtt": ["DataApiRole", "Arn"]}},
        },
    })


def _names(ctx, prefix: str) -> dict[str, str]:
    return {key: ctx.unique_name(f"{prefix}-{key[:3]}-")
            for key in ("bucket", "namespace", "workgroup", "profile")}


def _profiles(af, name: str) -> list:
    """The Redshift profiles AppFlow lists under ``name`` (an independent read of the Ref)."""
    found, kw = [], {"connectorType": "Redshift"}
    while True:
        page = af.describe_connector_profiles(**kw)
        found += [p for p in page["connectorProfileDetails"] if p["connectorProfileName"] == name]
        if not page.get("nextToken"):
            return found
        kw["nextToken"] = page["nextToken"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:representation",
      "plane:control")
def run(ctx) -> None:
    """A CloudFormation AppFlow ConnectorProfile for Redshift Serverless reads back through AppFlow.

    AppFlow lists it under its Ref with the templated properties and GetAtts; the stack delete
    removes it from that listing.
    """
    ec2 = ctx.client("ec2")
    cfn = ctx.client("cloudformation")
    af = ctx.client("appflow")
    azs = _usable_azs(ec2, 3)
    names = _names(ctx, "sim2real-afcp")

    stack_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-afcp-"),
                            _template(azs, names, "10.82"), Capabilities=["CAPABILITY_IAM"])
    status = wait_stack(cfn, stack_id, timeout_s=600.0)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    out = stack_outputs(cfn, stack_id)
    assert out["ConnectorProfileName"] == names["profile"], (
        f"Ref {out['ConnectorProfileName']!r} != the templated name {names['profile']!r}"
    )
    listed = _profiles(af, names["profile"])
    assert len(listed) == 1, f"profiles named {names['profile']!r}: {listed!r}"
    profile = listed[0]
    got = (profile["connectorProfileArn"], profile["credentialsArn"], profile["connectorType"],
           profile["connectionMode"])
    want = (out["ConnectorProfileArn"], out["CredentialsArn"], "Redshift", "Public")
    assert got == want, f"profile reads {got!r}, expected {want!r}"
    redshift = profile["connectorProfileProperties"]["Redshift"]
    got = {k: redshift.get(k) for k in ("bucketName", "roleArn", "dataApiRoleArn",
                                         "isRedshiftServerless", "workgroupName", "databaseName")}
    want = {"bucketName": names["bucket"], "roleArn": out["S3RoleArn"],
            "dataApiRoleArn": out["DataApiRoleArn"], "isRedshiftServerless": True,
            "workgroupName": names["workgroup"], "databaseName": _DB_NAME}
    assert got == want, f"Redshift properties {got!r}, expected {want!r}"

    delete_stack(cfn, stack_id)
    after = _profiles(af, names["profile"])
    assert after == [], f"profiles named {names['profile']!r} after the stack delete: {after!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
