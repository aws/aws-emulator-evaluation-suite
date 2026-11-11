"""list-studio-session-mappings-invalid-identity-type-filter-rejected."""
from __future__ import annotations

import json
import time

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-studio-session-mappings-invalid-identity-type-filter-rejected"
GROUP = "negative-classes"
SERVICES = ["emr"]


def _service_message(text, message, service="AWSEditors"):
    """`text` as the EMR backend `service` words a refusal; only its per-call request id is taken
    from the actual message."""
    request_id = (message or "").rsplit("Request ID: ", 1)[-1].split(";", 1)[0]
    return (
        f"{text} (Service: {service}; Status Code: 400; Error Code: InvalidRequestException; "
        f"Request ID: {request_id}; Proxy: null)"
    )


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListStudioSessionMappings with an IdentityType outside USER|GROUP fails with
    InvalidRequestException, HTTP 400 and AWS's exact message, while well-formed requests on the same
    Studio list no mappings before and after."""
    emr = ctx.client("emr")
    studio_id = _create_iam_studio(ctx)

    # Positive control: a well-formed call against the real Studio succeeds.
    resp = emr.list_studio_session_mappings(StudioId=studio_id)
    assert resp["SessionMappings"] == [], f"expected no mappings on a fresh Studio, got {resp['SessionMappings']}"

    # IdentityType's enum trait is not enforced by botocore's local parameter validation
    # (an out-of-enum value passes the SDK unmodified), so a plain client already reaches
    # the service; the unvalidated client just makes that independent of any future
    # botocore tightening.
    raw = _unvalidated_client(ctx, "emr")
    code, status, message = _error(
        lambda: raw.list_studio_session_mappings(StudioId=studio_id, IdentityType="ADMIN")
    )
    assert code == "InvalidRequestException", f"expected InvalidRequestException, got {code}"
    assert status == 400, f"expected HTTP 400, got {status!r}"
    expected = _service_message("IdentityType is not valid.", message)
    assert message == expected, f"expected the message {expected!r}, got {message!r}"

    # Effect absent: the Studio still has no session mappings after the rejected call.
    resp_after = emr.list_studio_session_mappings(StudioId=studio_id)
    assert resp_after["SessionMappings"] == [], (
        f"rejected call must not have altered the Studio's session mappings, "
        f"got {resp_after['SessionMappings']}"
    )


def _error(fn):
    """Call fn(); return its ClientError (code, HTTP status, message). An unexpected success raises rather
    than reading as an error-code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response["Error"]
        return error["Code"], exc.response["ResponseMetadata"]["HTTPStatusCode"], error.get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _unvalidated_client(ctx, service: str):
    return ctx.client(service, config=Config(parameter_validation=False))


def _create_studio_network(ctx):
    # An EMR Studio needs its own VPC/subnet, not an ambient default VPC: a freshly
    # provisioned account may not have one at all.
    ec2 = ctx.client("ec2")
    tag_spec = lambda resource_type: [
        {"ResourceType": resource_type, "Tags": [{"Key": "sim2real", "Value": "true"}]}
    ]
    vpc_id = ec2.create_vpc(
        CidrBlock="10.90.0.0/16", TagSpecifications=tag_spec("vpc")
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id, CidrBlock="10.90.1.0/24", TagSpecifications=tag_spec("subnet")
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_subnet", SubnetId=subnet_id))
    return vpc_id, [subnet_id]


def _create_studio_security_groups(ctx, vpc_id: str):
    ec2 = ctx.client("ec2")
    tag_spec = [
        {"ResourceType": "security-group", "Tags": [{"Key": "sim2real", "Value": "true"}]}
    ]
    workspace_sg = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-emr-studio-ws-"),
        Description="sim2real emr studio workspace sg",
        VpcId=vpc_id,
        TagSpecifications=tag_spec,
    )["GroupId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_security_group", GroupId=workspace_sg))
    engine_sg = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-emr-studio-en-"),
        Description="sim2real emr studio engine sg",
        VpcId=vpc_id,
        TagSpecifications=tag_spec,
    )["GroupId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_security_group", GroupId=engine_sg))
    return workspace_sg, engine_sg


def _create_studio_service_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-emr-studio-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "elasticmapreduce.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    # EMR Studio's service role must be able to read/write the DefaultS3Location bucket
    # and manage the Workspace<->cluster network channel, or CreateStudio itself rejects
    # the role up front.
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "s3:PutObject",
                    "s3:GetObject",
                    "s3:GetEncryptionConfiguration",
                    "s3:ListBucket",
                    "s3:DeleteObject",
                ],
                "Resource": "*",
            },
            {
                "Effect": "Allow",
                "Action": [
                    "ec2:CreateNetworkInterface",
                    "ec2:CreateNetworkInterfacePermission",
                    "ec2:DeleteNetworkInterface",
                    "ec2:DeleteNetworkInterfacePermission",
                    "ec2:DescribeNetworkInterfaces",
                    "ec2:ModifyNetworkInterfaceAttribute",
                    "ec2:AuthorizeSecurityGroupEgress",
                    "ec2:AuthorizeSecurityGroupIngress",
                    "ec2:CreateSecurityGroup",
                    "ec2:DescribeSecurityGroups",
                    "ec2:RevokeSecurityGroupEgress",
                    "ec2:DescribeTags",
                    "ec2:DescribeInstances",
                    "ec2:DescribeSubnets",
                    "ec2:DescribeVpcs",
                    "ec2:CreateTags",
                    "elasticmapreduce:ListInstances",
                    "elasticmapreduce:DescribeCluster",
                    "elasticmapreduce:ListSteps",
                ],
                "Resource": "*",
            },
        ],
    }
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="sim2real-emr-studio-inline",
        PolicyDocument=json.dumps(policy_doc),
    )
    ctx.on_cleanup(
        lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="sim2real-emr-studio-inline")
    )
    return iam.get_role(RoleName=role_name)["Role"]["Arn"]


def _create_studio_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-emr-studio-").lower().strip("-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": "true"}]})
    return f"s3://{bucket}/"


def _create_iam_studio(ctx) -> str:
    vpc_id, subnet_ids = _create_studio_network(ctx)
    workspace_sg, engine_sg = _create_studio_security_groups(ctx, vpc_id)
    role_arn = _create_studio_service_role(ctx)
    s3_location = _create_studio_bucket(ctx)
    emr = ctx.client("emr")
    # IAM trust policies are eventually consistent: EMR's assume check on a fresh service role
    # can fail for a few seconds, so retry (bounded).
    deadline = time.monotonic() + 90
    resp = None
    last_exc = None
    while time.monotonic() < deadline:
        try:
            resp = emr.create_studio(
                Name=ctx.unique_name("sim2real-emr-studio-"),
                AuthMode="IAM",
                VpcId=vpc_id,
                SubnetIds=subnet_ids,
                ServiceRole=role_arn,
                WorkspaceSecurityGroupId=workspace_sg,
                EngineSecurityGroupId=engine_sg,
                DefaultS3Location=s3_location,
                Tags=[{"Key": "sim2real", "Value": "true"}],
            )
            break
        except ClientError as exc:
            last_exc = exc
            if exc.response["Error"]["Code"] == "InvalidRequestException" and (
                "assume role" in str(exc) or "does not have permissions" in str(exc)
            ):
                time.sleep(5)
                continue
            raise
    if resp is None:
        raise last_exc
    studio_id = resp["StudioId"]
    ctx.on_cleanup(lambda: emr.delete_studio(StudioId=studio_id))
    return studio_id


# Resources in a VPC delete asynchronously: their ENIs linger, so an immediate DeleteSubnet /
# DeleteSecurityGroup / DeleteVpc fails with DependencyViolation. Wait (bounded) for the ENIs to go,
# retry DependencyViolation in that window, and raise naming the ENIs still attached.
_NET_TEARDOWN_S = 630.0
_NET_ENI_FILTER = {"VpcId": "vpc-id", "SubnetId": "subnet-id", "GroupId": "group-id"}
_NET_DEADLINES: dict = {}


def _delete_net(client, op, **ident):
    import time as _time

    from botocore.exceptions import ClientError as _ClientError

    held = _NET_DEADLINES.get(id(client))
    if held is None or held[0] is not client:
        held = _NET_DEADLINES[id(client)] = (client, _time.monotonic() + _NET_TEARDOWN_S)
    deadline = held[1]
    flt = [{"Name": _NET_ENI_FILTER[k], "Values": [v]} for k, v in ident.items() if k in _NET_ENI_FILTER]
    while _net_enis(client, flt) and _time.monotonic() < deadline:
        _time.sleep(10)
    while True:
        try:
            return getattr(client, op)(**ident)
        except _ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code != "DependencyViolation":
                raise
            if _time.monotonic() >= deadline:
                # Same exception type and code, so a caller catching ClientError still collects it.
                raise type(exc)(
                    {**exc.response, "Error": {**exc.response.get("Error", {}), "Message": (
                        f"{op}({ident}): DependencyViolation after {_NET_TEARDOWN_S}s; "
                        f"ENIs still attached: {_net_enis(client, flt)}"
                    )}},
                    exc.operation_name,
                ) from exc
        _time.sleep(10)


def _net_enis(client, flt):
    from botocore.exceptions import ClientError as _ClientError

    if not flt:
        return []
    try:
        enis = client.describe_network_interfaces(Filters=flt)["NetworkInterfaces"]
    except _ClientError:
        return []  # a diagnostic only: the delete itself still reports its own failure
    return [f"{e['NetworkInterfaceId']}:{e.get('InterfaceType') or e.get('Description', '')[:40]}" for e in enis]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
