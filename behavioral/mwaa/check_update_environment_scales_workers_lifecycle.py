"""update-environment-scales-workers-lifecycle."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-environment-scales-workers-lifecycle"
GROUP = "state"
SERVICES = ["mwaa"]

_ENV_TIMEOUT_S = 2700.0
_POLL_INTERVAL_S = 2.0


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateEnvironment on an AVAILABLE environment drives UPDATING -> AVAILABLE and persists the new value."""
    mwaa = ctx.client("mwaa")
    name = ctx.unique_name("sim2real-mwaa-env-")
    account = ctx.client("sts").get_caller_identity()["Account"]
    bucket_arn = _provision_bucket(ctx)
    role_arn = _provision_execution_role(ctx, account, name, bucket_arn)
    network = _provision_network(ctx)

    # mw1.micro allows exactly one worker ("The worker count for environment class mw1.micro must
    # be 1"), so the smallest class that can scale workers is mw1.small.
    _create_minimal_environment(ctx, name, network, bucket_arn, role_arn, EnvironmentClass="mw1.small")
    ctx.on_cleanup(lambda: _delete_environment_and_wait(ctx, name))
    _wait_for_environment_status(ctx, name, {"AVAILABLE"})

    mwaa.update_environment(Name=name, MaxWorkers=2)

    # The update must be observed transitioning through UPDATING before settling:
    # scaling MaxWorkers on real MWAA takes minutes, far longer than one poll
    # interval, so a target that never shows UPDATING never actually performed
    # the transition it reports.
    seen_updating = False
    deadline = time.monotonic() + _ENV_TIMEOUT_S
    final_env = None
    while time.monotonic() < deadline:
        env = mwaa.get_environment(Name=name)["Environment"]
        if env["Status"] == "UPDATING":
            seen_updating = True
        if env["Status"] == "AVAILABLE" and env.get("MaxWorkers") == 2:
            final_env = env
            break
        assert env["Status"] not in ("UPDATE_FAILED", "ROLLING_BACK", "CREATE_FAILED"), (
            f"update entered failure status {env['Status']}"
        )
        time.sleep(_POLL_INTERVAL_S)

    assert final_env is not None, "update never settled on AVAILABLE with MaxWorkers=2"
    assert final_env["LastUpdate"]["Status"] == "SUCCESS", (
        f"expected LastUpdate.Status SUCCESS, got {final_env['LastUpdate']}"
    )
    assert seen_updating, "update settled on AVAILABLE without ever observing UPDATING status"


# ===== helpers =====


def _error_code(fn):
    try:
        fn()
        return None
    except ClientError as e:
        return e.response["Error"]["Code"]


def _execution_role_policy(account, region, name, bucket_arn):
    """The AWS-owned-key sample execution-role policy from the MWAA execution-role docs.

    There is no attachable AWS-managed policy for an MWAA execution role
    (AmazonMWAAFullConsoleAccess is a console-user policy, not an execution-role
    policy) -- the role's permissions must be an inline policy scoped to this
    environment's own resources.
    """
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "airflow:PublishMetrics",
                "Resource": f"arn:aws:airflow:{region}:{account}:environment/{name}",
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


def _provision_execution_role(ctx, account, env_name, bucket_arn):
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
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "Name", "Value": role_name}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_name = ctx.unique_name("sim2real-mwaa-exec-policy-")
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps(
            _execution_role_policy(account, ctx.region, env_name, bucket_arn)
        ),
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
    s3.put_bucket_tagging(
        Bucket=bucket_name, Tagging={"TagSet": [{"Key": "Name", "Value": bucket_name}]}
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
    return [{"ResourceType": resource_type, "Tags": [{"Key": "Name", "Value": name}]}]


def _provision_network(ctx):
    ec2 = ctx.client("ec2")
    vpc_id = ec2.create_vpc(
        CidrBlock="10.192.0.0/16",
        TagSpecifications=_tag_spec("vpc", ctx.unique_name("sim2real-mwaa-vpc-")),
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsSupport={"Value": True})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsHostnames={"Value": True})
    azs = [az["ZoneName"] for az in ec2.describe_availability_zones()["AvailabilityZones"][:2]]

    igw_id = ec2.create_internet_gateway(
        TagSpecifications=_tag_spec("internet-gateway", ctx.unique_name("sim2real-mwaa-igw-"))
    )["InternetGateway"]["InternetGatewayId"]
    ec2.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)
    # Cleanups run last-registered first: detach the gateway, then delete it.
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_internet_gateway", InternetGatewayId=igw_id))
    ctx.on_cleanup(lambda: _delete_net(ec2, "detach_internet_gateway", InternetGatewayId=igw_id, VpcId=vpc_id))

    public_subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.192.0.0/24",
        AvailabilityZone=azs[0],
        TagSpecifications=_tag_spec("subnet", ctx.unique_name("sim2real-mwaa-pub-subnet-")),
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_subnet", SubnetId=public_subnet_id))
    public_rt_id = ec2.create_route_table(
        VpcId=vpc_id,
        TagSpecifications=_tag_spec("route-table", ctx.unique_name("sim2real-mwaa-pub-rt-")),
    )["RouteTable"]["RouteTableId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_route_table", RouteTableId=public_rt_id))
    ec2.create_route(RouteTableId=public_rt_id, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw_id)
    assoc_id = ec2.associate_route_table(RouteTableId=public_rt_id, SubnetId=public_subnet_id)[
        "AssociationId"
    ]
    ctx.on_cleanup(lambda: ec2.disassociate_route_table(AssociationId=assoc_id))

    alloc_id = ec2.allocate_address(
        Domain="vpc",
        TagSpecifications=_tag_spec("elastic-ip", ctx.unique_name("sim2real-mwaa-eip-")),
    )["AllocationId"]
    ctx.on_cleanup(lambda: ec2.release_address(AllocationId=alloc_id))
    nat_id = ec2.create_nat_gateway(
        SubnetId=public_subnet_id,
        AllocationId=alloc_id,
        TagSpecifications=_tag_spec("natgateway", ctx.unique_name("sim2real-mwaa-nat-")),
    )["NatGateway"]["NatGatewayId"]
    ec2.get_waiter("nat_gateway_available").wait(
        NatGatewayIds=[nat_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300}
    )
    ctx.on_cleanup(lambda: _delete_nat_gateway_and_wait(ec2, nat_id))

    private_rt_id = ec2.create_route_table(
        VpcId=vpc_id,
        TagSpecifications=_tag_spec("route-table", ctx.unique_name("sim2real-mwaa-priv-rt-")),
    )["RouteTable"]["RouteTableId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_route_table", RouteTableId=private_rt_id))
    ec2.create_route(RouteTableId=private_rt_id, DestinationCidrBlock="0.0.0.0/0", NatGatewayId=nat_id)

    private_subnet_ids = []
    for i, az in enumerate(azs):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.192.{i + 1}.0/24",
            AvailabilityZone=az,
            TagSpecifications=_tag_spec("subnet", ctx.unique_name(f"sim2real-mwaa-priv-subnet-{i}-")),
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
        TagSpecifications=_tag_spec("security-group", ctx.unique_name("sim2real-mwaa-sg-tag-")),
    )["GroupId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_security_group", GroupId=sg_id))
    ec2.authorize_security_group_ingress(
        GroupId=sg_id, IpPermissions=[{"IpProtocol": "-1", "UserIdGroupPairs": [{"GroupId": sg_id}]}]
    )
    return {"subnet_ids": private_subnet_ids, "security_group_id": sg_id}


def _call_with_retry(fn, *, timeout_s=120.0, interval_s=10.0):
    """Retries while ExecutionRoleArn has not yet propagated to MWAA's assume-role check."""
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            msg = str(exc)
            if code == "ValidationException" and "role" in msg.lower():
                last_exc = exc
                time.sleep(interval_s)
                continue
            raise
    raise last_exc


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
        Tags={"Name": name},
    )
    params.update(overrides)
    return _call_with_retry(lambda: mwaa.create_environment(**params))


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
