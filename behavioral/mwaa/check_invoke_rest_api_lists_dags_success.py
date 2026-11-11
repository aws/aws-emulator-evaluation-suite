"""invoke-rest-api-lists-dags-success."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "invoke-rest-api-lists-dags-success"
GROUP = "data-plane"
SERVICES = ["mwaa"]

_ENV_TIMEOUT_S = 2700.0
_POLL_INTERVAL_S = 2.0
_ROLE_PROPAGATION_TIMEOUT_S = 120.0

TAGS = {"sim2real:managed": "true", "sim2real-check": CHECK}
_TAG_KV = [{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real-check", "Value": CHECK}]


def _tag_spec(resource_type):
    return [{"ResourceType": resource_type, "Tags": _TAG_KV}]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """InvokeRestApi proxies a real Apache Airflow REST API call and returns a live 200 response."""
    mwaa = ctx.client("mwaa")
    name = ctx.unique_name("sim2real-mwaa-env-")
    bucket_arn = _provision_bucket(ctx)
    role_arn = _provision_execution_role(ctx, name, bucket_arn)
    network = _provision_network(ctx)

    _create_minimal_environment(ctx, name, network, bucket_arn, role_arn)
    ctx.on_cleanup(lambda: _delete_environment_and_wait(ctx, name))
    _wait_for_environment_status(ctx, name, {"AVAILABLE"})

    resp = mwaa.invoke_rest_api(Name=name, Path="/dags", Method="GET")

    assert resp["RestApiStatusCode"] == 200, (
        f"expected InvokeRestApi GET /dags to return 200, got {resp['RestApiStatusCode']}"
    )
    body = resp["RestApiResponse"]
    assert "dags" in body, f"expected the Airflow /dags response to contain 'dags', got keys {sorted(body)}"
    assert isinstance(body["dags"], list), (
        f"expected 'dags' to be a list, got {type(body['dags']).__name__}"
    )
    assert "total_entries" in body, (
        f"expected the Airflow /dags response to contain 'total_entries', got keys {sorted(body)}"
    )
    assert body["total_entries"] == len(body["dags"]), (
        f"expected total_entries ({body['total_entries']}) to equal len(dags) ({len(body['dags'])})"
    )


# ===== helpers =====


def _provision_execution_role(ctx, name, bucket_arn):
    iam = ctx.client("iam")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
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
        Tags=_TAG_KV,
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    # `AmazonMWAAFullConsoleAccess` grants a HUMAN console user permission to operate MWAA — it is
    # not attachable to an environment's own execution role and real AWS rejects it with
    # NoSuchEntity. The execution role instead needs the scoped inline policy AWS documents for it:
    # S3 access to its own DAG bucket, log access to its own log group, metric publishing, and the
    # Celery executor's SQS queue.
    execution_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "airflow:PublishMetrics",
                "Resource": f"arn:aws:airflow:{ctx.region}:{account_id}:environment/{name}",
            },
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject*", "s3:GetBucket*", "s3:List*"],
                "Resource": [bucket_arn, f"{bucket_arn}/*"],
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
                "Resource": f"arn:aws:logs:{ctx.region}:{account_id}:log-group:airflow-{name}-*",
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
                "Resource": f"arn:aws:sqs:{ctx.region}:*:airflow-celery-*",
            },
            {
                "Effect": "Allow",
                "Action": ["kms:Decrypt", "kms:DescribeKey", "kms:GenerateDataKey*", "kms:Encrypt"],
                "NotResource": f"arn:aws:kms:*:{account_id}:key/*",
                "Condition": {"StringEquals": {"kms:ViaService": [f"sqs.{ctx.region}.amazonaws.com"]}},
            },
        ],
    }
    policy_name = "sim2real-mwaa-execution-policy"
    iam.put_role_policy(
        RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(execution_policy)
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role_arn


def _provision_bucket(ctx):
    s3 = ctx.client("s3")
    bucket_name = ctx.unique_name("sim2real-mwaa-bkt-").lower().replace("_", "-")
    # us-east-1 is the one region where CreateBucket rejects an explicit LocationConstraint.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket_name)
    else:
        s3.create_bucket(
            Bucket=bucket_name, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket_name))
    s3.put_bucket_tagging(Bucket=bucket_name, Tagging={"TagSet": _TAG_KV})
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


def _provision_network(ctx):
    ec2 = ctx.client("ec2")
    vpc_id = ec2.create_vpc(CidrBlock="10.192.0.0/16", TagSpecifications=_tag_spec("vpc"))["Vpc"][
        "VpcId"
    ]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsSupport={"Value": True})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsHostnames={"Value": True})
    azs = [az["ZoneName"] for az in ec2.describe_availability_zones()["AvailabilityZones"][:2]]

    igw_id = ec2.create_internet_gateway(TagSpecifications=_tag_spec("internet-gateway"))[
        "InternetGateway"
    ]["InternetGatewayId"]
    ec2.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)
    # Cleanups run last-registered first: detach the gateway, then delete it.
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_internet_gateway", InternetGatewayId=igw_id))
    ctx.on_cleanup(lambda: _delete_net(ec2, "detach_internet_gateway", InternetGatewayId=igw_id, VpcId=vpc_id))

    public_subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.192.0.0/24",
        AvailabilityZone=azs[0],
        TagSpecifications=_tag_spec("subnet"),
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_subnet", SubnetId=public_subnet_id))
    public_rt_id = ec2.create_route_table(VpcId=vpc_id, TagSpecifications=_tag_spec("route-table"))[
        "RouteTable"
    ]["RouteTableId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_route_table", RouteTableId=public_rt_id))
    ec2.create_route(RouteTableId=public_rt_id, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw_id)
    assoc_id = ec2.associate_route_table(RouteTableId=public_rt_id, SubnetId=public_subnet_id)[
        "AssociationId"
    ]
    ctx.on_cleanup(lambda: ec2.disassociate_route_table(AssociationId=assoc_id))

    alloc_id = ec2.allocate_address(Domain="vpc", TagSpecifications=_tag_spec("elastic-ip"))[
        "AllocationId"
    ]
    ctx.on_cleanup(lambda: ec2.release_address(AllocationId=alloc_id))
    nat_id = ec2.create_nat_gateway(
        SubnetId=public_subnet_id,
        AllocationId=alloc_id,
        TagSpecifications=_tag_spec("natgateway"),
    )["NatGateway"]["NatGatewayId"]
    ec2.get_waiter("nat_gateway_available").wait(
        NatGatewayIds=[nat_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300}
    )
    ctx.on_cleanup(lambda: _delete_nat_gateway_and_wait(ec2, nat_id))

    private_rt_id = ec2.create_route_table(VpcId=vpc_id, TagSpecifications=_tag_spec("route-table"))[
        "RouteTable"
    ]["RouteTableId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_route_table", RouteTableId=private_rt_id))
    ec2.create_route(RouteTableId=private_rt_id, DestinationCidrBlock="0.0.0.0/0", NatGatewayId=nat_id)

    private_subnet_ids = []
    for i, az in enumerate(azs):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.192.{i + 1}.0/24",
            AvailabilityZone=az,
            TagSpecifications=_tag_spec("subnet"),
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
        TagSpecifications=_tag_spec("security-group"),
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
        Tags=TAGS,
    )
    params.update(overrides)
    deadline = time.monotonic() + _ROLE_PROPAGATION_TIMEOUT_S
    while True:
        try:
            return mwaa.create_environment(**params)
        except ClientError as e:
            error = e.response["Error"]
            # A role created moments ago is not always immediately assumable everywhere IAM
            # writes propagate to; retry only that specific, transient rejection.
            role_not_yet_propagated = error["Code"] == "ValidationException" and "role" in error.get(
                "Message", ""
            ).lower()
            if not role_not_yet_propagated or time.monotonic() >= deadline:
                raise
            time.sleep(2)


def _wait_for_environment_status(ctx, name, target_statuses, timeout_s=_ENV_TIMEOUT_S):
    mwaa = ctx.client("mwaa")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        env = mwaa.get_environment(Name=name)["Environment"]
        last = env["Status"]
        if last in target_statuses:
            return env
        if last.endswith("_FAILED") and last not in target_statuses:
            raise AssertionError(f"environment entered failure status {last}")
        time.sleep(_POLL_INTERVAL_S)
    raise AssertionError(f"environment did not reach {target_statuses} within {timeout_s}s (last={last})")


def _delete_environment_and_wait(ctx, name, timeout_s=1800.0):
    mwaa = ctx.client("mwaa")
    try:
        mwaa.delete_environment(Name=name)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
        return
    deadline = time.monotonic() + timeout_s
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
