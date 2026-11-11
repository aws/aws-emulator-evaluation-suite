"""cli-token-native-airflow-cli-round-trip."""
from __future__ import annotations

import base64
import json
import time
import urllib.error
import urllib.parse
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cli-token-native-airflow-cli-round-trip"
GROUP = "native-protocol"
SERVICES = ["mwaa"]

_ENV_TIMEOUT_S = 2700.0
_POLL_INTERVAL_S = 2.0


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """CreateCliToken issues a token that authenticates a direct HTTPS call to the real Airflow
    webserver's aws_mwaa/cli endpoint (the native protocol beyond the AWS control-plane API) and
    executes a genuine Airflow CLI command."""
    mwaa = ctx.client("mwaa")
    name = ctx.unique_name("sim2real-mwaa-env-")
    bucket_arn = _provision_bucket(ctx)
    role_arn = _provision_execution_role(ctx, name, bucket_arn)
    network = _provision_network(ctx)

    _create_minimal_environment(ctx, name, network, bucket_arn, role_arn)
    ctx.on_cleanup(lambda: _delete_environment_and_wait(ctx, name))
    _wait_for_environment_status(ctx, name, {"AVAILABLE"})

    token_resp = mwaa.create_cli_token(Name=name)
    cli_token = token_resp["CliToken"]
    hostname = token_resp["WebServerHostname"]
    assert hostname

    url = f"{ctx.endpoint_url(hostname)}/aws_mwaa/cli"
    # The webserver can answer 307 to the CLI path; a 307 keeps the method and body (RFC 9110),
    # which urllib does not do for a POST, so follow it here, bounded.
    for _ in range(3):
        req = urllib.request.Request(
            url=url,
            data=b"dags list",
            method="POST",
            headers={
                "Authorization": f"Bearer {cli_token}",
                "Content-Type": "text/plain",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                status = resp.status
                payload = json.loads(resp.read().decode("utf-8"))
            break
        except urllib.error.HTTPError as e:
            location = e.headers.get("Location")
            if e.code in (307, 308) and location:
                url = urllib.parse.urljoin(url, location)
                continue
            raise AssertionError(
                f"aws_mwaa/cli returned HTTP {e.code} (Location={location!r}): {e.read()!r}"
            ) from e
    else:
        raise AssertionError(f"aws_mwaa/cli kept redirecting; last Location {url!r}")

    assert status == 200
    assert "stdout" in payload
    stdout_text = base64.b64decode(payload["stdout"]).decode("utf-8", errors="replace")
    stderr_text = base64.b64decode(payload["stderr"]).decode("utf-8", errors="replace") if payload.get(
        "stderr"
    ) else ""
    # A genuine, working Airflow CLI prints the (empty) dag table header; a stub that
    # cannot actually run the CLI will error out or return something else entirely.
    assert "dag_id" in stdout_text.lower() or "no data found" in stdout_text.lower(), (
        f"unexpected CLI stdout: {stdout_text!r} stderr: {stderr_text!r}"
    )


# ===== helpers =====


def _provision_execution_role(ctx, name, bucket_arn):
    """The environment's real MWAA execution-role policy (S3 DAG bucket, airflow-* log groups,
    the Celery executor's SQS queue, PublishMetrics, and the SQS-scoped KMS grant), as in
    https://docs.aws.amazon.com/mwaa/latest/userguide/mwaa-create-role.html.
    ``AmazonMWAAFullConsoleAccess`` is a console-user policy, not an execution-role policy."""
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
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    execution_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "airflow:PublishMetrics",
                "Resource": f"arn:aws:airflow:{ctx.region}:{account_id}:environment/{name}",
            },
            {
                "Effect": "Deny",
                "Action": "s3:ListAllMyBuckets",
                "Resource": [bucket_arn, f"{bucket_arn}/*"],
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
            {"Effect": "Allow", "Action": "logs:DescribeLogGroups", "Resource": "*"},
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
    policy_name = f"{role_name}-exec"
    iam.put_role_policy(
        RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(execution_policy)
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    _wait_for_inline_policy(iam, role_name, policy_name)
    return role_arn


def _wait_for_inline_policy(iam, role_name, policy_name, timeout_s=60.0):
    """Bound the wait for IAM's eventually-consistent read-your-writes on an independent read,
    rather than hoping a fixed sleep is long enough."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        names = iam.list_role_policies(RoleName=role_name)["PolicyNames"]
        if policy_name in names:
            return
        time.sleep(2)
    raise AssertionError(
        f"inline policy {policy_name} did not appear on role {role_name} within {timeout_s}s"
    )


def _provision_bucket(ctx):
    s3 = ctx.client("s3")
    bucket_name = ctx.unique_name("sim2real-mwaa-bkt-").lower().replace("_", "-")
    # us-east-1 is the one region where CreateBucket rejects an explicit LocationConstraint;
    # ctx.region still drives where the bucket actually lands, so this is not a pinned region.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket_name)
    else:
        s3.create_bucket(
            Bucket=bucket_name, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket_name))
    s3.put_bucket_tagging(
        Bucket=bucket_name, Tagging={"TagSet": [{"Key": "sim2real-check", "Value": CHECK}]}
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


def _tag_spec(resource_type):
    return {"ResourceType": resource_type, "Tags": [{"Key": "sim2real-check", "Value": CHECK}]}


def _provision_network(ctx):
    ec2 = ctx.client("ec2")
    vpc_id = ec2.create_vpc(CidrBlock="10.192.0.0/16", TagSpecifications=[_tag_spec("vpc")])[
        "Vpc"
    ]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsSupport={"Value": True})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsHostnames={"Value": True})
    azs = [az["ZoneName"] for az in ec2.describe_availability_zones()["AvailabilityZones"][:2]]

    igw_id = ec2.create_internet_gateway(TagSpecifications=[_tag_spec("internet-gateway")])[
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
        TagSpecifications=[_tag_spec("subnet")],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_subnet", SubnetId=public_subnet_id))
    public_rt_id = ec2.create_route_table(
        VpcId=vpc_id, TagSpecifications=[_tag_spec("route-table")]
    )["RouteTable"]["RouteTableId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_route_table", RouteTableId=public_rt_id))
    ec2.create_route(RouteTableId=public_rt_id, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw_id)
    assoc_id = ec2.associate_route_table(RouteTableId=public_rt_id, SubnetId=public_subnet_id)[
        "AssociationId"
    ]
    ctx.on_cleanup(lambda: ec2.disassociate_route_table(AssociationId=assoc_id))

    alloc_id = ec2.allocate_address(Domain="vpc", TagSpecifications=[_tag_spec("elastic-ip")])[
        "AllocationId"
    ]
    ctx.on_cleanup(lambda: ec2.release_address(AllocationId=alloc_id))
    nat_id = ec2.create_nat_gateway(
        SubnetId=public_subnet_id,
        AllocationId=alloc_id,
        TagSpecifications=[_tag_spec("natgateway")],
    )["NatGateway"]["NatGatewayId"]
    ec2.get_waiter("nat_gateway_available").wait(
        NatGatewayIds=[nat_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300}
    )
    ctx.on_cleanup(lambda: _delete_nat_gateway_and_wait(ec2, nat_id))

    private_rt_id = ec2.create_route_table(
        VpcId=vpc_id, TagSpecifications=[_tag_spec("route-table")]
    )["RouteTable"]["RouteTableId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_route_table", RouteTableId=private_rt_id))
    ec2.create_route(RouteTableId=private_rt_id, DestinationCidrBlock="0.0.0.0/0", NatGatewayId=nat_id)

    private_subnet_ids = []
    for i, az in enumerate(azs):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.192.{i + 1}.0/24",
            AvailabilityZone=az,
            TagSpecifications=[_tag_spec("subnet")],
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
        TagSpecifications=[_tag_spec("security-group")],
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
        Tags={"sim2real-check": CHECK},
    )
    params.update(overrides)
    return mwaa.create_environment(**params)


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
