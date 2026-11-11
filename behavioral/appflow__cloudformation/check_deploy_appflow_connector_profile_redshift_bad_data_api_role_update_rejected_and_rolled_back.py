"""deploy-appflow-connector-profile-redshift-bad-data-api-role-update-rejected-and-rolled-back."""
from __future__ import annotations

import json
import re
import time

from behavioral_harness import tags

CHECK = "deploy-appflow-connector-profile-redshift-bad-data-api-role-update-rejected-and-rolled-back"
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


# ---- Check-specific: the template, then run(). ----

_DB_NAME = "sim2realdb"
_TAG_KEY = "sim2real-afcp"


def _usable_azs(ec2, count: int) -> list[str]:
    """The first ``count`` available AZs by name.

    Redshift Serverless does not support every AZ id; an account whose first zones it does not
    support fails at the workgroup create, not at this pick.
    """
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


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:deploy", "concern:negative-classes",
      "plane:control")
def run(ctx) -> None:
    """Updating an AppFlow ConnectorProfile's DataApiRoleArn to a role AppFlow cannot assume fails.

    AppFlow's connection test refuses the role, and the stack and the same, unreplaced profile
    roll back to the original role.
    """
    ec2 = ctx.client("ec2")
    cfn = ctx.client("cloudformation")
    af = ctx.client("appflow")
    azs = _usable_azs(ec2, 3)
    names = _names(ctx, "sim2real-afcpu")

    stack_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-afcpu-"),
                            _template(azs, names, "10.84"), Capabilities=["CAPABILITY_IAM"])
    status = wait_stack(cfn, stack_id, timeout_s=600.0)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    out = stack_outputs(cfn, stack_id)
    before = _profiles(af, out["ConnectorProfileName"])
    assert len(before) == 1, f"profiles named {out['ConnectorProfileName']!r}: {before!r}"
    before = before[0]
    role = before["connectorProfileProperties"]["Redshift"]["dataApiRoleArn"]
    assert role == out["DataApiRoleArn"], f"control dataApiRoleArn {role!r}"

    # The one property changed: a well-formed role ARN in this account that does not exist.
    bad_role_arn = (f"arn:{stack_id.split(':')[1]}:iam::{ctx.account}:role/"
                    f"{ctx.unique_name('sim2real-afcpu-norole-')}")
    cfn.update_stack(StackName=stack_id, TemplateBody=_template(azs, names, "10.84", bad_role_arn),
                     Capabilities=["CAPABILITY_IAM"])
    status = wait_stack(cfn, stack_id, timeout_s=600.0)
    assert status == "UPDATE_ROLLBACK_COMPLETE", f"rejected update ended {status!r}"
    got = handler_reason(
        failed_reason(stack_events(cfn, stack_id), "ConnectorProfile", "UPDATE_FAILED"),
        ctx.account)
    want = (
        "Error while communicating to connector: The test connection request failed due to: "
        "com.amazonaws.sandstoneconfigurationservicelambda.coral.model.ConnectorServerException: "
        'Failed to validate Connection while attempting "select distinct(table_schema) from '
        'information_schema.tables limit 1" with connector failure The request for the  Redshift '
        "failed with the status code 403: AccessDenied while trying to assume user-provided "
        f"{masked(bad_role_arn, ctx.account)} role by AppFlow service principal. "
        "(Service: null; Status Code: 400; Error Code: Client; Request ID: <id>; Proxy: null) "
        "(Service: Appflow, Status Code: 400, Request ID: <id>) (SDK Attempt Count: <n>)",
        "GeneralServiceException",
    )
    assert got == want, f"ConnectorProfile reason {got!r}, expected {want!r}"

    # The same profile (server-minted ARN, credentials and creation time) with the original role.
    after = _profiles(af, out["ConnectorProfileName"])
    assert len(after) == 1, f"profiles after the rollback: {after!r}"
    after = after[0]
    keys = ("connectorProfileArn", "credentialsArn", "createdAt")
    assert [after[k] for k in keys] == [before[k] for k in keys], (
        f"the rollback replaced the profile: {[after[k] for k in keys]!r}"
    )
    role = after["connectorProfileProperties"]["Redshift"]["dataApiRoleArn"]
    assert role == out["DataApiRoleArn"], f"dataApiRoleArn after the rollback {role!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
