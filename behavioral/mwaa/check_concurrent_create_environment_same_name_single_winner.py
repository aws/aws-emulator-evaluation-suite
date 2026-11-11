"""concurrent-create-environment-same-name-single-winner."""
from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-create-environment-same-name-single-winner"
GROUP = "concurrency"
SERVICES = ["mwaa"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Racing CreateEnvironment calls for one Name produce exactly one winner, every other racer fails
    with ValidationException "An environment with name ... already exists", and GetEnvironment
    returns the winner's role and bucket.
    """
    mwaa = ctx.client("mwaa")
    name = ctx.unique_name("sim2real-mwaa-env-")
    bucket_arn = _provision_bucket(ctx)
    role_arn = _provision_execution_role(ctx, bucket_arn)
    network = _provision_network(ctx)
    ctx.on_cleanup(lambda: _delete_environment_and_wait(ctx, name))

    racers = 4

    def _attempt(_i):
        try:
            _create_minimal_environment(ctx, name, network, bucket_arn, role_arn)
            return ("ok", None)
        except ClientError as e:
            return ("error", (e.response["Error"]["Code"], e.response["Error"].get("Message")))

    with ThreadPoolExecutor(max_workers=racers) as pool:
        results = list(pool.map(_attempt, range(racers)))

    successes = [r for r in results if r[0] == "ok"]
    failures = [r for r in results if r[0] == "error"]

    assert len(successes) == 1, f"expected exactly 1 winner, got {len(successes)}: {results}"
    assert len(failures) == racers - 1
    expected_message = f"An environment with name {name} already exists. Please use other name."
    for _, (code, message) in failures:
        assert code == "ValidationException", code
        assert message == expected_message, message

    # The record at the destination is the winner's own environment, not a stub echo:
    # its role/bucket must match what the winning CreateEnvironment call actually sent.
    env = mwaa.get_environment(Name=name)["Environment"]
    assert env["Name"] == name
    assert env["ExecutionRoleArn"] == role_arn, (
        f"expected winner's role {role_arn}, got {env.get('ExecutionRoleArn')}"
    )
    assert env["SourceBucketArn"] == bucket_arn, (
        f"expected winner's bucket {bucket_arn}, got {env.get('SourceBucketArn')}"
    )

    # DeleteEnvironment refuses a CREATING environment, and creation plus deletion outlast the
    # teardown budget, so the run waits (within its own budget) for creation to settle.
    _wait_creation_settled(ctx, mwaa, name)


# ===== helpers =====


def _provision_execution_role(ctx, bucket_arn):
    iam = ctx.client("iam")
    bucket_name = bucket_arn.split(":::", 1)[1]
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
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": role_name}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    # The MWAA execution role needs an inline policy (see
    # https://docs.aws.amazon.com/mwaa/latest/userguide/mwaa-create-role.html);
    # AmazonMWAAFullConsoleAccess is a console-user policy, not an execution-role policy.
    policy_name = "sim2real-mwaa-execution-policy"
    region, account = ctx.region, ctx.client("sts").get_caller_identity()["Account"]
    inline_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "airflow:PublishMetrics",
                "Resource": f"arn:aws:airflow:{region}:{account}:environment/*",
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
                    "logs:DescribeLogGroups",
                ],
                "Resource": f"arn:aws:logs:{region}:{account}:log-group:airflow-*",
            },
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
        ],
    }
    iam.put_role_policy(
        RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(inline_policy)
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    _wait_for_inline_policy_visible(iam, role_name, policy_name)
    return role_arn


def _wait_for_inline_policy_visible(iam, role_name, policy_name, timeout_s=30.0):
    # Bound the wait on IAM's own read of the policy instead of a blind sleep for cross-service
    # (MWAA) propagation of the just-written inline policy.
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        names = iam.list_role_policies(RoleName=role_name)["PolicyNames"]
        if policy_name in names:
            return
        time.sleep(2)
    raise AssertionError(
        f"inline policy {policy_name} not visible on role {role_name} within {timeout_s}s"
    )


def _provision_bucket(ctx):
    s3 = ctx.client("s3")
    bucket_name = ctx.unique_name("sim2real-mwaa-bkt-").lower().replace("_", "-")
    if ctx.region == "us-east-1":
        # S3 CreateBucket rejects an explicit LocationConstraint for us-east-1; checks run
        # in us-west-2, so this branch only guards the API's own quirk, not a region pin.
        s3.create_bucket(Bucket=bucket_name)
    else:
        s3.create_bucket(
            Bucket=bucket_name, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket_name))
    s3.put_bucket_tagging(
        Bucket=bucket_name, Tagging={"TagSet": [{"Key": "sim2real", "Value": bucket_name}]}
    )
    s3.put_object(Bucket=bucket_name, Key="dags/")
    ctx.on_cleanup(lambda: s3.delete_object(Bucket=bucket_name, Key="dags/"))
    return f"arn:aws:s3:::{bucket_name}"


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


def _tag_spec(resource_type, name):
    return [{"ResourceType": resource_type, "Tags": [{"Key": "sim2real", "Value": name}]}]


def _provision_network(ctx):
    ec2 = ctx.client("ec2")
    vpc_name = ctx.unique_name("sim2real-mwaa-vpc-")
    vpc_id = ec2.create_vpc(
        CidrBlock="10.192.0.0/16", TagSpecifications=_tag_spec("vpc", vpc_name)
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsSupport={"Value": True})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsHostnames={"Value": True})
    azs = [az["ZoneName"] for az in ec2.describe_availability_zones()["AvailabilityZones"][:2]]

    igw_id = ec2.create_internet_gateway(TagSpecifications=_tag_spec("internet-gateway", vpc_name))[
        "InternetGateway"
    ]["InternetGatewayId"]
    ec2.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)
    ctx.on_cleanup(lambda: _detach_igw(ec2, igw_id, vpc_id))
    ctx.on_cleanup(lambda: _detach_and_delete_igw(ec2, igw_id, vpc_id))

    public_subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.192.0.0/24",
        AvailabilityZone=azs[0],
        TagSpecifications=_tag_spec("subnet", f"{vpc_name}-public"),
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_subnet", SubnetId=public_subnet_id))
    public_rt_id = ec2.create_route_table(
        VpcId=vpc_id, TagSpecifications=_tag_spec("route-table", f"{vpc_name}-public")
    )["RouteTable"]["RouteTableId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_route_table", RouteTableId=public_rt_id))
    ec2.create_route(RouteTableId=public_rt_id, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw_id)
    assoc_id = ec2.associate_route_table(RouteTableId=public_rt_id, SubnetId=public_subnet_id)[
        "AssociationId"
    ]
    ctx.on_cleanup(lambda: ec2.disassociate_route_table(AssociationId=assoc_id))

    alloc_id = ec2.allocate_address(
        Domain="vpc", TagSpecifications=_tag_spec("elastic-ip", vpc_name)
    )["AllocationId"]
    ctx.on_cleanup(lambda: ec2.release_address(AllocationId=alloc_id))
    nat_id = ec2.create_nat_gateway(
        SubnetId=public_subnet_id,
        AllocationId=alloc_id,
        TagSpecifications=_tag_spec("natgateway", vpc_name),
    )["NatGateway"]["NatGatewayId"]
    ec2.get_waiter("nat_gateway_available").wait(
        NatGatewayIds=[nat_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300}
    )
    ctx.on_cleanup(lambda: _delete_nat_gateway_and_wait(ec2, nat_id))

    private_rt_id = ec2.create_route_table(
        VpcId=vpc_id, TagSpecifications=_tag_spec("route-table", f"{vpc_name}-private")
    )["RouteTable"]["RouteTableId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_route_table", RouteTableId=private_rt_id))
    ec2.create_route(RouteTableId=private_rt_id, DestinationCidrBlock="0.0.0.0/0", NatGatewayId=nat_id)

    private_subnet_ids = []
    for i, az in enumerate(azs):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.192.{i + 1}.0/24",
            AvailabilityZone=az,
            TagSpecifications=_tag_spec("subnet", f"{vpc_name}-private-{i}"),
        )["Subnet"]["SubnetId"]
        ctx.on_cleanup(lambda sid=subnet_id: _delete_net(ec2, "delete_subnet", SubnetId=sid))
        assoc = ec2.associate_route_table(RouteTableId=private_rt_id, SubnetId=subnet_id)[
            "AssociationId"
        ]
        ctx.on_cleanup(lambda aid=assoc: ec2.disassociate_route_table(AssociationId=aid))
        private_subnet_ids.append(subnet_id)

    sg_name = ctx.unique_name("sim2real-mwaa-sg-")
    sg_id = ec2.create_security_group(
        VpcId=vpc_id,
        GroupName=sg_name,
        Description="mwaa behavioral check security group",
        TagSpecifications=_tag_spec("security-group", sg_name),
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
        WebserverAccessMode="PRIVATE_ONLY",
        Tags={"sim2real": name},
    )
    params.update(overrides)
    return mwaa.create_environment(**params)


def _wait_creation_settled(ctx, mwaa, name, timeout_s=3600.0):
    """Wait every 2 s until the environment leaves CREATING, to ``timeout_s`` cut to the run's time left."""
    left = ctx.time_left()
    deadline = time.monotonic() + (timeout_s if left is None else min(timeout_s, left - 60.0))
    while time.monotonic() < deadline:
        if mwaa.get_environment(Name=name)["Environment"]["Status"] not in ("CREATING", "PENDING"):
            return
        time.sleep(2)


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
