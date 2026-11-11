"""submit-attachment-state-changes-updates-attachment-status."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "submit-attachment-state-changes-updates-attachment-status"
GROUP = "server-side"
SERVICES = ["ecs"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """SubmitAttachmentStateChanges moves an awsvpc task's ENI attachment from ATTACHING to
    ATTACHED, as the ECS agent reports it, and DescribeTasks shows the new status."""
    ecs = ctx.client("ecs")

    net = _own_network(ctx)
    subnet_id, vpc_id, security_group_id = net["subnet_ids"][0], net["vpc_id"], net["sg_id"]

    cluster_arn = _create_cluster(ctx)
    # RegisterContainerInstance validates the identity document/signature pair and rejects a
    # synthetic one, so fetch a genuine pair from a running EC2 instance via SSM.
    doc, sig = _launch_identity_source_instance(ctx, subnet_id)
    _register_container_instance(ctx, cluster_arn, doc, sig, vpc_id, subnet_id)
    task_def_arn = _register_awsvpc_task_def(ctx, ecs)


    run_resp = ecs.run_task(
        cluster=cluster_arn,
        taskDefinition=task_def_arn,
        launchType="EC2",
        count=1,
        networkConfiguration={
            "awsvpcConfiguration": {
                "subnets": [subnet_id],
                "securityGroups": [security_group_id],
                "assignPublicIp": "DISABLED",
            }
        },
    )
    assert not run_resp.get("failures"), f"RunTask failures: {run_resp.get('failures')}"
    task_arn = run_resp["tasks"][0]["taskArn"]
    ctx.on_cleanup(lambda: _safe(lambda: ecs.stop_task(cluster=cluster_arn, task=task_arn)))
    ctx.on_cleanup(
        lambda: _safe(lambda: ecs.submit_task_state_change(cluster=cluster_arn, task=task_arn, status="STOPPED"))
    )

    def _get_task():
        return ecs.describe_tasks(cluster=cluster_arn, tasks=[task_arn])["tasks"][0]

    # The attachment moves PRECREATED -> ATTACHING -> ATTACHED; ECS makes the first step itself
    # and rejects a direct PRECREATED -> ATTACHED submission, so wait for ATTACHING first.
    with_attachment = _poll_until(
        _get_task,
        lambda t: bool(t.get("attachments")) and t["attachments"][0].get("status") == "ATTACHING",
        timeout_s=60.0,
    )
    attachment = with_attachment["attachments"][0]
    assert attachment["type"] == "ElasticNetworkInterface"
    initial_status = attachment["status"]
    assert initial_status == "ATTACHING", (
        f"expected the attachment to be ATTACHING (the only status SubmitAttachmentStateChanges "
        f"may legally transition to ATTACHED from) before our explicit report, got {initial_status!r}"
    )

    attachment_arn = _resolve_attachment_arn(ctx, attachment["id"])

    ecs.submit_attachment_state_changes(
        cluster=cluster_arn,
        attachments=[{"attachmentArn": attachment_arn, "status": "ATTACHED"}],
    )

    attached_task = _poll_until(
        _get_task,
        lambda t: bool(t.get("attachments")) and t["attachments"][0]["status"] == "ATTACHED",
        timeout_s=30.0,
    )
    assert attached_task["attachments"][0]["status"] == "ATTACHED"




def _safe(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ClusterNotFoundException":
            raise


def _poll_until(probe, predicate, timeout_s=30.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


_NET_TAGS = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
]


def _own_network(ctx):
    """Create a VPC with one public subnet (so the identity-source instance can reach SSM) and
    return {"vpc_id", "subnet_ids", "sg_id"}; its cleanup is registered first so it runs last and
    waits out Fargate ENIs that linger after the tasks stop."""
    ec2 = ctx.client("ec2")
    vpc_id = ec2.create_vpc(
        CidrBlock="10.198.0.0/24",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": _NET_TAGS}],
    )["Vpc"]["VpcId"]
    state = {"subnet_id": None, "igw_id": None}

    def _teardown_network():
        deadline = time.monotonic() + 540
        subnet_id, igw_id = state["subnet_id"], state["igw_id"]
        if subnet_id:
            while time.monotonic() < deadline:
                enis = ec2.describe_network_interfaces(
                    Filters=[{"Name": "subnet-id", "Values": [subnet_id]}]
                ).get("NetworkInterfaces", [])
                if not enis:
                    break
                time.sleep(10)
            while True:
                try:
                    ec2.delete_subnet(SubnetId=subnet_id)
                    break
                except ClientError as exc:
                    if exc.response["Error"]["Code"] == "InvalidSubnetID.NotFound":
                        break
                    if time.monotonic() >= deadline:
                        raise
                    time.sleep(10)
        if igw_id:
            ec2.detach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)
            ec2.delete_internet_gateway(InternetGatewayId=igw_id)
        while True:
            try:
                ec2.delete_vpc(VpcId=vpc_id)
                break
            except ClientError as exc:
                if exc.response["Error"]["Code"] == "InvalidVpcID.NotFound":
                    break
                if time.monotonic() >= deadline:
                    raise
                time.sleep(10)

    ctx.on_cleanup(_teardown_network)
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsSupport={"Value": True})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsHostnames={"Value": True})
    az = ec2.describe_availability_zones()["AvailabilityZones"][0]["ZoneName"]
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.198.0.0/25",
        AvailabilityZone=az,
        TagSpecifications=[{"ResourceType": "subnet", "Tags": _NET_TAGS}],
    )["Subnet"]["SubnetId"]
    state["subnet_id"] = subnet_id
    ec2.modify_subnet_attribute(SubnetId=subnet_id, MapPublicIpOnLaunch={"Value": True})
    igw_id = ec2.create_internet_gateway(
        TagSpecifications=[{"ResourceType": "internet-gateway", "Tags": _NET_TAGS}]
    )["InternetGateway"]["InternetGatewayId"]
    ec2.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)
    state["igw_id"] = igw_id
    rt_id = ec2.describe_route_tables(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])[
        "RouteTables"
    ][0]["RouteTableId"]
    ec2.create_route(RouteTableId=rt_id, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw_id)
    sg_id = ec2.describe_security_groups(
        Filters=[
            {"Name": "vpc-id", "Values": [vpc_id]},
            {"Name": "group-name", "Values": ["default"]},
        ]
    )["SecurityGroups"][0]["GroupId"]
    return {"vpc_id": vpc_id, "subnet_ids": [subnet_id], "sg_id": sg_id}


def _resolve_attachment_arn(ctx, raw_id: str) -> str:
    """Normalize an attachment id to the full ARN SubmitAttachmentStateChanges expects;
    DescribeTasks may return either the bare id or the ARN."""
    if raw_id.startswith("arn:"):
        return raw_id
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    return f"arn:aws:ecs:{ctx.region}:{account_id}:attachment/{raw_id}"


def _create_cluster(ctx) -> str:
    ecs = ctx.client("ecs")
    name = ctx.unique_name("sim2real-behav-cl-")
    cluster_arn = ecs.create_cluster(clusterName=name)["cluster"]["clusterArn"]
    ctx.on_cleanup(lambda: _safe(lambda: ecs.delete_cluster(cluster=cluster_arn)))
    return cluster_arn


def _register_container_instance(ctx, cluster_arn: str, doc: str, sig: str, vpc_id: str, subnet_id: str) -> str:
    ecs = ctx.client("ecs")
    # RunTask placement checks the registered capability attributes; awsvpc needs
    # ecs.capability.task-eni plus ecs.vpc-id/ecs.subnet-id matching the task's subnet.
    attributes = [
        {"name": f"com.amazonaws.ecs.capability.docker-remote-api.1.{minor}"} for minor in range(17, 45)
    ] + [
        {"name": "ecs.capability.task-eni"},
        {"name": "ecs.capability.task-eni.ipv6"},
        {"name": "ecs.vpc-id", "value": vpc_id},
        {"name": "ecs.subnet-id", "value": subnet_id},
    ]
    resp = ecs.register_container_instance(
        cluster=cluster_arn,
        instanceIdentityDocument=doc,
        instanceIdentityDocumentSignature=sig,
        totalResources=[
            {"name": "CPU", "type": "INTEGER", "integerValue": 4096},
            {"name": "MEMORY", "type": "INTEGER", "integerValue": 4096},
            {"name": "PORTS", "type": "STRINGSET", "stringSetValue": []},
            {"name": "PORTS_UDP", "type": "STRINGSET", "stringSetValue": []},
        ],
        versionInfo={"agentVersion": "1.0.0", "dockerVersion": "DockerVersion: 20.10.7"},
        attributes=attributes,
    )
    arn = resp["containerInstance"]["containerInstanceArn"]
    ctx.on_cleanup(
        lambda: _safe(
            lambda: ecs.deregister_container_instance(
                cluster=cluster_arn, containerInstance=arn, force=True
            )
        )
    )
    return arn


def _ignore_client_error(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("InvalidInstanceID.NotFound", "NoSuchEntity"):
            raise


def _launch_identity_source_instance(ctx, subnet_id: str):
    """Launch an EC2 instance in the task's subnet behind an SSM instance profile and return its
    AWS-signed (identity_document_json, identity_document_signature) fetched via SSM Run Command;
    registers cleanup for everything it creates."""
    ec2 = ctx.client("ec2")
    iam = ctx.client("iam")
    ssm = ctx.client("ssm")

    role_name = ctx.unique_name("sim2real-ci-ssm-role-")
    try:
        iam.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {"Service": "ec2.amazonaws.com"},
                            "Action": "sts:AssumeRole",
                        }
                    ],
                }
            ),
        )
    except ClientError as exc:
        raise AssertionError(f"cannot create an IAM role for the identity-fetch instance: {exc}")
    ctx.on_cleanup(lambda: _ignore_client_error(lambda: iam.delete_role(RoleName=role_name)))
    ssm_policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=ssm_policy_arn)
    ctx.on_cleanup(
        lambda: _ignore_client_error(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=ssm_policy_arn))
    )
    profile_name = role_name
    iam.create_instance_profile(InstanceProfileName=profile_name)
    ctx.on_cleanup(lambda: _ignore_client_error(lambda: iam.delete_instance_profile(InstanceProfileName=profile_name)))
    iam.add_role_to_instance_profile(InstanceProfileName=profile_name, RoleName=role_name)
    ctx.on_cleanup(
        lambda: _ignore_client_error(
            lambda: iam.remove_role_from_instance_profile(InstanceProfileName=profile_name, RoleName=role_name)
        )
    )

    # IAM role/instance-profile propagation lag before EC2 will accept it as a launch parameter.
    def _profile_visible():
        try:
            iam.get_instance_profile(InstanceProfileName=profile_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
            return False
        return True

    _poll_until(_profile_visible, bool, timeout_s=15.0, interval_s=2.0)

    ami_id = ssm.get_parameter(
        Name="/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
    )["Parameter"]["Value"]

    instance_id = None
    last_err = None
    # EC2 can reject a new instance profile as "Invalid IAM Instance Profile name" after IAM
    # already shows it; retry that specific error until a deadline.
    deadline = time.monotonic() + 90.0
    while time.monotonic() < deadline:
        try:
            reservation = ec2.run_instances(
                ImageId=ami_id,
                InstanceType="t3.micro",
                MinCount=1,
                MaxCount=1,
                SubnetId=subnet_id,
                IamInstanceProfile={"Name": profile_name},
                TagSpecifications=[
                    {
                        "ResourceType": "instance",
                        "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-ci-identity-")}],
                    }
                ],
            )
            instance_id = reservation["Instances"][0]["InstanceId"]
            break
        except ClientError as exc:
            last_err = exc
            if exc.response["Error"]["Code"] == "InvalidParameterValue" and "IAM Instance Profile" in str(exc):
                time.sleep(5.0)
                continue
            raise
    if instance_id is None:
        raise AssertionError(f"could not launch the identity-fetch EC2 instance: {last_err}")
    ctx.on_cleanup(lambda: _ignore_client_error(lambda: ec2.terminate_instances(InstanceIds=[instance_id])))

    def _instance_state():
        # Immediately after run_instances, the instance ID can be momentarily unknown to
        # DescribeInstances (eventual consistency) and raise InvalidInstanceID.NotFound;
        # treat that as "not running yet" rather than letting it propagate.
        try:
            return ec2.describe_instances(InstanceIds=[instance_id])["Reservations"][0]["Instances"][0]["State"][
                "Name"
            ]
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "InvalidInstanceID.NotFound":
                return "pending-not-visible-yet"
            raise

    _poll_until(
        _instance_state,
        lambda state: state == "running",
        timeout_s=60.0,
        interval_s=5.0,
    )

    def _ssm_ping_status():
        info = ssm.describe_instance_information(Filters=[{"Key": "InstanceIds", "Values": [instance_id]}])[
            "InstanceInformationList"
        ]
        return info[0]["PingStatus"] if info else None

    _poll_until(_ssm_ping_status, lambda status: status == "Online", timeout_s=180.0, interval_s=5.0)

    command_id = ssm.send_command(
        InstanceIds=[instance_id],
        DocumentName="AWS-RunShellScript",
        Parameters={
            "commands": [
                # IMDSv2 is enforced (a token-less GET returns 401 with an empty body): fetch a token first.
                "TOKEN=$(curl -s -X PUT http://169.254.169.254/latest/api/token "
                "-H 'X-aws-ec2-metadata-token-ttl-seconds: 60')",
                "curl -s -H \"X-aws-ec2-metadata-token: $TOKEN\" "
                "http://169.254.169.254/latest/dynamic/instance-identity/document",
                "echo SIM2REAL_SPLIT",
                "curl -s -H \"X-aws-ec2-metadata-token: $TOKEN\" "
                "http://169.254.169.254/latest/dynamic/instance-identity/signature",
            ]
        },
    )["Command"]["CommandId"]

    def _invocation():
        try:
            return ssm.get_command_invocation(CommandId=command_id, InstanceId=instance_id)
        except ClientError:
            return {"Status": "Pending"}

    invocation = _poll_until(
        _invocation,
        lambda inv: inv.get("Status") in ("Success", "Failed", "Cancelled", "TimedOut"),
        timeout_s=30.0,
        interval_s=3.0,
    )
    if invocation.get("Status") != "Success":
        raise AssertionError(f"identity-document SSM command did not succeed: {invocation.get('Status')!r}")

    doc_str, _, sig_str = invocation["StandardOutputContent"].partition("SIM2REAL_SPLIT")
    doc_str = doc_str.strip()
    sig_str = sig_str.strip()
    if not doc_str or not sig_str:
        raise AssertionError(
            "identity document/signature retrieval produced empty output: "
            f"stdout={invocation.get('StandardOutputContent')!r} "
            f"stderr={invocation.get('StandardErrorContent')!r}"
        )
    return doc_str, sig_str


def _register_awsvpc_task_def(ctx, ecs) -> str:
    family = ctx.unique_name("sim2real-behav-td-")
    resp = ecs.register_task_definition(
        family=family,
        networkMode="awsvpc",
        requiresCompatibilities=["EC2"],
        containerDefinitions=[
            {
                "name": "app",
                "image": "public.ecr.aws/docker/library/busybox:1.36",
                "memory": 128,
                "essential": True,
            }
        ],
    )
    arn = resp["taskDefinition"]["taskDefinitionArn"]
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, arn))
    return arn


def _retire_task_definition(ecs, task_definition: str) -> None:
    """Deregister a task definition revision, then delete it: a deregistered revision stays
    INACTIVE until DeleteTaskDefinitions removes it. An already-deleted revision is fine; any
    other failure raises."""
    from botocore.exceptions import ClientError

    try:
        described = ecs.describe_task_definition(taskDefinition=task_definition)["taskDefinition"]
    except ClientError as exc:
        if "Unable to describe task definition" in exc.response["Error"].get("Message", ""):
            return
        raise
    arn = described["taskDefinitionArn"]
    if described["status"] == "DELETE_IN_PROGRESS":
        return
    if described["status"] == "ACTIVE":
        ecs.deregister_task_definition(taskDefinition=arn)
    failures = ecs.delete_task_definitions(taskDefinitions=[arn]).get("failures", [])
    if failures:
        raise RuntimeError(f"task definition {arn} teardown failed: {failures}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
