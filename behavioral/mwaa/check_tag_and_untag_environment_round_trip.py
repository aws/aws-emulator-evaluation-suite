"""tag-and-untag-environment-round-trip."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-and-untag-environment-round-trip"
GROUP = "data-plane"
SERVICES = ["mwaa"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource/UntagResource mutate the tag set observed via ListTagsForResource on a real environment."""
    mwaa = ctx.client("mwaa")
    account = ctx.client("sts").get_caller_identity()["Account"]
    name = ctx.unique_name("sim2real-mwaa-env-")
    bucket_arn, bucket_name = _provision_bucket(ctx)
    role_arn = _provision_execution_role(ctx, name, bucket_name, account)
    network = _provision_network(ctx)

    # Tagging does not require the environment to be AVAILABLE; the Arn is
    # returned synchronously and DeleteEnvironment accepts any status, so we
    # avoid the ~20-30 minute wait to AVAILABLE for this check.
    created = _create_minimal_environment(
        ctx, name, network, bucket_arn, role_arn, Tags={"sim2real-purpose": "initial"}
    )
    arn = created["Arn"]
    ctx.on_cleanup(lambda: _delete_environment_and_wait(ctx, name))

    tags = mwaa.list_tags_for_resource(ResourceArn=arn)["Tags"]
    assert tags.get("sim2real-purpose") == "initial", (
        f"expected the tag set from CreateEnvironment to be visible via "
        f"ListTagsForResource, got sim2real-purpose={tags.get('sim2real-purpose')!r}"
    )

    mwaa.tag_resource(ResourceArn=arn, Tags={"sim2real-extra": "added"})
    tags = mwaa.list_tags_for_resource(ResourceArn=arn)["Tags"]
    assert tags.get("sim2real-purpose") == "initial", (
        f"expected TagResource to leave the pre-existing tag intact, got "
        f"sim2real-purpose={tags.get('sim2real-purpose')!r}"
    )
    assert tags.get("sim2real-extra") == "added", (
        f"expected TagResource's new tag to be visible via ListTagsForResource, got "
        f"sim2real-extra={tags.get('sim2real-extra')!r}"
    )

    mwaa.untag_resource(ResourceArn=arn, tagKeys=["sim2real-extra"])
    tags = mwaa.list_tags_for_resource(ResourceArn=arn)["Tags"]
    assert "sim2real-extra" not in tags, (
        f"expected UntagResource to remove the key, but ListTagsForResource still "
        f"returned sim2real-extra={tags.get('sim2real-extra')!r}"
    )
    assert tags.get("sim2real-purpose") == "initial", (
        f"expected UntagResource to leave the untouched tag intact, got "
        f"sim2real-purpose={tags.get('sim2real-purpose')!r}"
    )


# ===== helpers =====


def _execution_role_policy(region, account, name, bucket_name):
    # There is no attachable AWS-managed policy for an MWAA execution role.
    # `arn:aws:iam::aws:policy/AmazonMWAAFullConsoleAccess` is a console-access policy for a
    # human/IAM principal, not something an execution role can carry: real AWS returns NoSuchEntity
    # for it on AttachRolePolicy. This is the actual documented execution-role contract per
    # https://docs.aws.amazon.com/mwaa/latest/userguide/mwaa-create-role.html.
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "airflow:PublishMetrics",
                "Resource": f"arn:aws:airflow:{region}:{account}:environment/{name}",
            },
            {
                "Effect": "Deny",
                "Action": "s3:ListAllMyBuckets",
                "Resource": [f"arn:aws:s3:::{bucket_name}", f"arn:aws:s3:::{bucket_name}/*"],
            },
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject*", "s3:GetBucket*", "s3:List*"],
                "Resource": [f"arn:aws:s3:::{bucket_name}", f"arn:aws:s3:::{bucket_name}/*"],
            },
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
                    "logs:DescribeLogStreams",
                ],
                "Resource": [f"arn:aws:logs:{region}:{account}:log-group:airflow-{name}-*"],
            },
            {"Effect": "Allow", "Action": ["logs:DescribeLogGroups"], "Resource": ["*"]},
            {"Effect": "Allow", "Action": ["s3:GetAccountPublicAccessBlock"], "Resource": ["*"]},
            {"Effect": "Allow", "Action": "cloudwatch:PutMetricData", "Resource": "*"},
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
                "Resource": f"arn:aws:sqs:{region}:*:airflow-celery-*",
            },
            {
                "Effect": "Allow",
                "Action": ["kms:Decrypt", "kms:DescribeKey", "kms:GenerateDataKey*", "kms:Encrypt"],
                "NotResource": f"arn:aws:kms:*:{account}:key/*",
                "Condition": {"StringLike": {"kms:ViaService": [f"sqs.{region}.amazonaws.com"]}},
            },
        ],
    }


def _provision_execution_role(ctx, env_name, bucket_name, account):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-mwaa-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": ["airflow.amazonaws.com", "airflow-env.amazonaws.com"]},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy)
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_name = "sim2real-mwaa-execution-policy"
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps(_execution_role_policy(ctx.region, account, env_name, bucket_name)),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role_arn


def _provision_bucket(ctx):
    s3 = ctx.client("s3")
    bucket_name = ctx.unique_name("sim2real-mwaa-bkt-").lower().replace("_", "-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket_name)
    else:
        s3.create_bucket(
            Bucket=bucket_name, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket_name))
    s3.put_object(Bucket=bucket_name, Key="dags/")
    ctx.on_cleanup(lambda: s3.delete_object(Bucket=bucket_name, Key="dags/"))
    return f"arn:aws:s3:::{bucket_name}", bucket_name


def _delete_nat_gateway_and_wait(ec2, nat_id):
    ec2.delete_nat_gateway(NatGatewayId=nat_id)
    deadline = time.monotonic() + 300
    state = None
    while time.monotonic() < deadline:
        state = ec2.describe_nat_gateways(NatGatewayIds=[nat_id])["NatGateways"][0]["State"]
        if state in ("deleted", "failed"):
            return
        time.sleep(2)
    raise AssertionError(f"NAT gateway {nat_id} not deleted within 300s (last state {state})")


def _release_address_retrying(ec2, alloc_id):
    # The EIP cannot release until the NAT gateway that holds it is gone; a short bounded retry
    # covers the window right after the NAT gateway finishes deleting.
    deadline = time.monotonic() + 30.0
    while True:
        try:
            ec2.release_address(AllocationId=alloc_id)
            return
        except ClientError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(2)


def _provision_network(ctx):
    ec2 = ctx.client("ec2")
    vpc_id = ec2.create_vpc(CidrBlock="10.192.0.0/16")["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsSupport={"Value": True})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsHostnames={"Value": True})
    azs = [az["ZoneName"] for az in ec2.describe_availability_zones()["AvailabilityZones"][:2]]

    igw_id = ec2.create_internet_gateway()["InternetGateway"]["InternetGatewayId"]
    ec2.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)
    ctx.on_cleanup(lambda: _detach_igw(ec2, igw_id, vpc_id))
    ctx.on_cleanup(lambda: _detach_and_delete_igw(ec2, igw_id, vpc_id))

    public_subnet_id = ec2.create_subnet(
        VpcId=vpc_id, CidrBlock="10.192.0.0/24", AvailabilityZone=azs[0]
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_subnet", SubnetId=public_subnet_id))
    public_rt_id = ec2.create_route_table(VpcId=vpc_id)["RouteTable"]["RouteTableId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_route_table", RouteTableId=public_rt_id))
    ec2.create_route(RouteTableId=public_rt_id, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw_id)
    assoc_id = ec2.associate_route_table(RouteTableId=public_rt_id, SubnetId=public_subnet_id)[
        "AssociationId"
    ]
    ctx.on_cleanup(lambda: ec2.disassociate_route_table(AssociationId=assoc_id))

    alloc_id = ec2.allocate_address(Domain="vpc")["AllocationId"]
    ctx.on_cleanup(lambda: _release_address_retrying(ec2, alloc_id))
    nat_id = ec2.create_nat_gateway(SubnetId=public_subnet_id, AllocationId=alloc_id)[
        "NatGateway"
    ]["NatGatewayId"]
    ec2.get_waiter("nat_gateway_available").wait(
        NatGatewayIds=[nat_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300}
    )
    ctx.on_cleanup(lambda: _delete_nat_gateway_and_wait(ec2, nat_id))

    private_rt_id = ec2.create_route_table(VpcId=vpc_id)["RouteTable"]["RouteTableId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_route_table", RouteTableId=private_rt_id))
    ec2.create_route(RouteTableId=private_rt_id, DestinationCidrBlock="0.0.0.0/0", NatGatewayId=nat_id)

    private_subnet_ids = []
    for i, az in enumerate(azs):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id, CidrBlock=f"10.192.{i + 1}.0/24", AvailabilityZone=az
        )["Subnet"]["SubnetId"]
        ctx.on_cleanup(lambda sid=subnet_id: _delete_net(ec2, "delete_subnet", SubnetId=sid))
        assoc = ec2.associate_route_table(RouteTableId=private_rt_id, SubnetId=subnet_id)[
            "AssociationId"
        ]
        ctx.on_cleanup(lambda aid=assoc: ec2.disassociate_route_table(AssociationId=aid))
        private_subnet_ids.append(subnet_id)

    sg_id = ec2.create_security_group(
        VpcId=vpc_id,
        GroupName=ctx.unique_name("sim2real-mwaa-sg-"),
        Description="mwaa behavioral check security group",
    )["GroupId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_security_group", GroupId=sg_id))
    ec2.authorize_security_group_ingress(
        GroupId=sg_id, IpPermissions=[{"IpProtocol": "-1", "UserIdGroupPairs": [{"GroupId": sg_id}]}]
    )
    return {"subnet_ids": private_subnet_ids, "security_group_id": sg_id}


def _create_minimal_environment(ctx, name, network, bucket_arn, role_arn, **overrides):
    mwaa = ctx.client("mwaa")
    params = dict(
        Name=name,
        ExecutionRoleArn=role_arn,
        SourceBucketArn=bucket_arn,
        DagS3Path="dags",
        NetworkConfiguration={
            "SubnetIds": network["subnet_ids"],
            "SecurityGroupIds": [network["security_group_id"]],
        },
        EnvironmentClass="mw1.micro",
        MaxWorkers=1,
        MinWorkers=1,
        WebserverAccessMode="PUBLIC_ONLY",
    )
    params.update(overrides)
    # The execution role was just created and its policy just attached; MWAA can reject the
    # role as not-yet-assumable before IAM propagates it. Bounded retry on that specific
    # rejection rather than a fixed sleep before the first attempt.
    deadline = time.monotonic() + 120
    last_err = None
    while time.monotonic() < deadline:
        try:
            return mwaa.create_environment(**params)
        except ClientError as e:
            last_err = e
            if e.response["Error"]["Code"] == "AccessDeniedException":
                time.sleep(5)
                continue
            raise
    raise AssertionError(
        f"CreateEnvironment kept rejecting the just-created execution role after "
        f"retrying for IAM propagation: {last_err}"
    )


def _delete_environment_and_wait(ctx, name, timeout_s=2520.0):
    """Teardown: delete the environment once its running operation ends, then wait it out."""
    # 2520 s plus the network teardown's waits stays inside the suite's 3600 s cleanup budget.
    mwaa = ctx.client("mwaa")
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            mwaa.delete_environment(Name=name)
            break
        except ClientError as e:
            error = e.response["Error"]
            if error["Code"] == "ResourceNotFoundException":
                return
            busy = "must complete previous operation" in error.get("Message", "")
            if error["Code"] != "ValidationException" or not busy or time.monotonic() >= deadline:
                raise
        time.sleep(2)
    while time.monotonic() < deadline:
        try:
            mwaa.get_environment(Name=name)
        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(2)
    raise AssertionError(f"MWAA environment {name} still present {timeout_s}s after DeleteEnvironment")


# EC2 network teardown waits for AWS-managed ENIs to leave before it deletes: a resource in this VPC
# deletes asynchronously, so DeleteSubnet/DeleteSecurityGroup/DeleteVpc fail with DependencyViolation
# until its ENIs go. That code is retried to one deadline shared by the check's network deletes.
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
        _time.sleep(2)
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
        _time.sleep(2)


def _detach_igw(ec2, igw_id, vpc_id):
    """Teardown: detach the internet gateway; one already detached or deleted needs nothing."""
    try:
        _delete_net(ec2, "detach_internet_gateway", InternetGatewayId=igw_id, VpcId=vpc_id)
    except ClientError as exc:
        gone = ("Gateway.NotAttached", "InvalidInternetGatewayID.NotFound")
        if exc.response["Error"]["Code"] not in gone:
            raise


def _detach_and_delete_igw(ec2, igw_id, vpc_id):
    """Teardown: detach, then delete the internet gateway, which refuses deletion while attached."""
    _detach_igw(ec2, igw_id, vpc_id)
    _delete_net(ec2, "delete_internet_gateway", InternetGatewayId=igw_id)


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
