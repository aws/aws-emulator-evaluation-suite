"""update-environment-during-creation-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-environment-during-creation-rejected"
GROUP = "overly-permissive"
SERVICES = ["mwaa"]

_ENV_TIMEOUT_S = 2700.0
_POLL_INTERVAL_S = 2.0

_TAG_KEY = "sim2real-check"


def _ec2_tag_spec(resource_type: str) -> list[dict]:
    return [{"ResourceType": resource_type, "Tags": [{"Key": _TAG_KEY, "Value": CHECK}]}]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateEnvironment on a CREATING environment fails with ValidationException and its exact message
    and leaves MaxWorkers at 1; once AVAILABLE, the same update sets MaxWorkers to 5.
    """
    mwaa = ctx.client("mwaa")
    name = ctx.unique_name("sim2real-mwaa-env-")
    role_arn = _provision_execution_role(ctx)
    bucket_arn = _provision_bucket(ctx)
    network = _provision_network(ctx)

    _create_environment_with_role_propagation_retry(ctx, name, network, bucket_arn, role_arn)
    ctx.on_cleanup(lambda: _delete_environment_and_wait(ctx, name))

    status_at_attempt = mwaa.get_environment(Name=name)["Environment"]["Status"]
    assert status_at_attempt in ("CREATING", "PENDING"), (
        f"environment already left the creating phase ({status_at_attempt}); cannot exercise "
        "the state-conflict boundary"
    )

    code, message = _error(lambda: mwaa.update_environment(Name=name, MaxWorkers=5))
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    assert message == (
        "Environments with CREATING status must complete previous operation before initiating a "
        "new operation."
    ), message

    # Effect absent: the rejected update must not have persisted.
    env = mwaa.get_environment(Name=name)["Environment"]
    assert env["MaxWorkers"] == 1, f"expected MaxWorkers unchanged at 1, got {env['MaxWorkers']!r}"

    # Positive control: once AVAILABLE, the identical shape of update succeeds.
    _wait_for_environment_status(ctx, name, {"AVAILABLE"})
    mwaa.update_environment(Name=name, MaxWorkers=5)
    final_env = _wait_for_environment_status(
        ctx, name, {"AVAILABLE"}, timeout_s=_ENV_TIMEOUT_S, require_field=("MaxWorkers", 5)
    )
    assert final_env["MaxWorkers"] == 5, f"expected MaxWorkers=5 after the accepted update, got {final_env['MaxWorkers']!r}"


def _error(fn):
    """Call fn(); return its (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded and returned {result!r}")


def _provision_execution_role(ctx):
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
        Tags=[{"Key": _TAG_KEY, "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    # "arn:aws:iam::aws:policy/AmazonMWAAFullConsoleAccess" does not exist as an
    # attachable policy on real AWS (AttachRolePolicy -> NoSuchEntity) — it is a
    # console-user policy, not an execution-role policy. This is the AWS-documented
    # minimum execution-role permission set instead.
    execution_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": "airflow:PublishMetrics", "Resource": "*"},
            {"Effect": "Allow", "Action": ["s3:GetObject*", "s3:GetBucket*", "s3:List*"], "Resource": "*"},
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
                "Resource": "*",
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
                "Resource": "*",
            },
            {
                "Effect": "Allow",
                "Action": ["kms:Decrypt", "kms:DescribeKey", "kms:GenerateDataKey*", "kms:Encrypt"],
                "Resource": "*",
            },
        ],
    }
    policy_name = "sim2real-mwaa-exec"
    iam.put_role_policy(
        RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(execution_policy)
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role_arn


def _provision_bucket(ctx):
    s3 = ctx.client("s3")
    bucket_name = ctx.unique_name("sim2real-mwaa-bkt-").lower().replace("_", "-")
    # "us-east-1" here is the S3 CreateBucket API quirk (that region rejects an
    # explicit LocationConstraint), not a pinned resource region — ctx.region drives
    # bucket placement either way.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket_name)
    else:
        s3.create_bucket(
            Bucket=bucket_name, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket_name))
    s3.put_bucket_tagging(Bucket=bucket_name, Tagging={"TagSet": [{"Key": _TAG_KEY, "Value": CHECK}]})
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


def _detach_and_delete_igw(ec2, igw_id, vpc_id):
    """Detach, then delete: DeleteInternetGateway refuses a gateway still attached to a VPC."""
    _delete_net(ec2, "detach_internet_gateway", InternetGatewayId=igw_id, VpcId=vpc_id)
    _delete_net(ec2, "delete_internet_gateway", InternetGatewayId=igw_id)


def _provision_network(ctx):
    ec2 = ctx.client("ec2")
    vpc_id = ec2.create_vpc(
        CidrBlock="10.192.0.0/16", TagSpecifications=_ec2_tag_spec("vpc")
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsSupport={"Value": True})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsHostnames={"Value": True})
    azs = [az["ZoneName"] for az in ec2.describe_availability_zones()["AvailabilityZones"][:2]]

    igw_id = ec2.create_internet_gateway(TagSpecifications=_ec2_tag_spec("internet-gateway"))[
        "InternetGateway"
    ]["InternetGatewayId"]
    ec2.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)
    ctx.on_cleanup(lambda: _detach_and_delete_igw(ec2, igw_id, vpc_id))

    public_subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.192.0.0/24",
        AvailabilityZone=azs[0],
        TagSpecifications=_ec2_tag_spec("subnet"),
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_subnet", SubnetId=public_subnet_id))
    public_rt_id = ec2.create_route_table(
        VpcId=vpc_id, TagSpecifications=_ec2_tag_spec("route-table")
    )["RouteTable"]["RouteTableId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_route_table", RouteTableId=public_rt_id))
    ec2.create_route(RouteTableId=public_rt_id, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw_id)
    assoc_id = ec2.associate_route_table(RouteTableId=public_rt_id, SubnetId=public_subnet_id)[
        "AssociationId"
    ]
    ctx.on_cleanup(lambda: ec2.disassociate_route_table(AssociationId=assoc_id))

    alloc_id = ec2.allocate_address(Domain="vpc", TagSpecifications=_ec2_tag_spec("elastic-ip"))[
        "AllocationId"
    ]
    ctx.on_cleanup(lambda: ec2.release_address(AllocationId=alloc_id))
    nat_id = ec2.create_nat_gateway(
        SubnetId=public_subnet_id,
        AllocationId=alloc_id,
        TagSpecifications=_ec2_tag_spec("natgateway"),
    )["NatGateway"]["NatGatewayId"]
    ec2.get_waiter("nat_gateway_available").wait(
        NatGatewayIds=[nat_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300}
    )
    ctx.on_cleanup(lambda: _delete_nat_gateway_and_wait(ec2, nat_id))

    private_rt_id = ec2.create_route_table(
        VpcId=vpc_id, TagSpecifications=_ec2_tag_spec("route-table")
    )["RouteTable"]["RouteTableId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_route_table", RouteTableId=private_rt_id))
    ec2.create_route(RouteTableId=private_rt_id, DestinationCidrBlock="0.0.0.0/0", NatGatewayId=nat_id)

    private_subnet_ids = []
    for i, az in enumerate(azs):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.192.{i + 1}.0/24",
            AvailabilityZone=az,
            TagSpecifications=_ec2_tag_spec("subnet"),
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
        TagSpecifications=_ec2_tag_spec("security-group"),
    )["GroupId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_security_group", GroupId=sg_id))
    ec2.authorize_security_group_ingress(
        GroupId=sg_id, IpPermissions=[{"IpProtocol": "-1", "UserIdGroupPairs": [{"GroupId": sg_id}]}]
    )
    return {"subnet_ids": private_subnet_ids, "security_group_id": sg_id}


def _create_environment_with_role_propagation_retry(ctx, name, network, bucket_arn, role_arn):
    """CreateEnvironment retrying while the freshly created execution role's
    trust/permissions propagate, bounded rather than an unconditional sleep."""
    deadline = time.monotonic() + 90.0
    last_err = None
    while time.monotonic() < deadline:
        try:
            return _create_minimal_environment(ctx, name, network, bucket_arn, role_arn)
        except ClientError as exc:
            last_err = exc
            time.sleep(5)
            continue
    raise AssertionError(f"could not create environment after role propagation wait: {last_err}")


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
        # mw1.micro fixes the worker count at 1, so the class must allow the MaxWorkers=5 update.
        EnvironmentClass="mw1.small",
        MaxWorkers=1,
        MinWorkers=1,
        WebserverAccessMode="PRIVATE_ONLY",
        Tags={_TAG_KEY: CHECK},
    )
    params.update(overrides)
    return mwaa.create_environment(**params)


def _wait_for_environment_status(
    ctx, name, target_statuses, timeout_s=_ENV_TIMEOUT_S, require_field=None
):
    mwaa = ctx.client("mwaa")
    left = ctx.time_left()
    deadline = time.monotonic() + (timeout_s if left is None else min(timeout_s, left))
    last = None
    while time.monotonic() < deadline:
        env = mwaa.get_environment(Name=name)["Environment"]
        last = env["Status"]
        if last in target_statuses:
            if require_field is None or env.get(require_field[0]) == require_field[1]:
                return env
        if last.endswith("_FAILED") and last not in target_statuses:
            raise AssertionError(f"environment entered failure status {last}")
        time.sleep(_POLL_INTERVAL_S)
    raise AssertionError(f"environment did not reach {target_statuses} within {timeout_s}s (last={last})")


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


# EC2 network teardown waits for AWS-managed ENIs to leave before it deletes. A load balancer,
# directory, endpoint, cluster, function or instance in this VPC deletes ASYNCHRONOUSLY: its delete
# returns while its ENIs still sit in the subnet / security group, so an immediate DeleteSubnet /
# DeleteSecurityGroup / DeleteVpc fails with DependencyViolation -- and swallowing that leaked the
# VPC while the check PASSED. So wait (bounded) for the resource's ENIs to go, retry
# DependencyViolation inside the same window, and raise a final failure naming the ENIs still
# attached. Every other error propagates. Teardown-only: nothing run() executes calls this, so it
# cannot change the verdict. The window is shared by all of one check's network deletes.
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
