"""discover-poll-endpoint-returns-endpoint-for-registered-instance."""
from __future__ import annotations

import json
import time
import urllib.parse

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "discover-poll-endpoint-returns-endpoint-for-registered-instance"
GROUP = "server-side"
SERVICES = ["ecs"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DiscoverPollEndpoint returns https endpoint and telemetryEndpoint URLs for a registered
    container instance, identical across repeated calls (the agent re-polls on reconnect)."""
    ecs = ctx.client("ecs")

    cluster_arn = _create_cluster(ctx)
    # RegisterContainerInstance rejects an omitted or synthetic identity document/signature,
    # so a real instance's AWS-signed pair is fetched via SSM Run Command.
    doc, sig = _launch_identity_source_instance(ctx)
    container_instance_arn = _register_container_instance(ctx, cluster_arn, doc, sig)

    resp = ecs.discover_poll_endpoint(cluster=cluster_arn, containerInstance=container_instance_arn)


    endpoint = resp.get("endpoint")
    telemetry_endpoint = resp.get("telemetryEndpoint")
    assert endpoint, f"DiscoverPollEndpoint returned no endpoint: {resp}"
    assert endpoint.startswith("https://"), f"endpoint is not an https URL: {endpoint}"
    assert urllib.parse.urlsplit(endpoint).hostname, f"endpoint carries no host: {endpoint}"
    assert telemetry_endpoint, f"DiscoverPollEndpoint returned no telemetryEndpoint: {resp}"
    assert telemetry_endpoint.startswith("https://"), f"telemetryEndpoint is not an https URL: {telemetry_endpoint}"

    # The agent calls this on every reconnect, so the same pair must come back unchanged.
    resp2 = ecs.discover_poll_endpoint(cluster=cluster_arn, containerInstance=container_instance_arn)
    assert resp2.get("endpoint"), "second DiscoverPollEndpoint call for the same instance returned no endpoint"
    assert resp2["endpoint"] == endpoint, (
        f"endpoint changed across repeated DiscoverPollEndpoint calls: {endpoint!r} -> {resp2['endpoint']!r}"
    )
    assert resp2.get("telemetryEndpoint") == telemetry_endpoint, (
        f"telemetryEndpoint changed across repeated DiscoverPollEndpoint calls: "
        f"{telemetry_endpoint!r} -> {resp2.get('telemetryEndpoint')!r}"
    )




def _safe(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ClusterNotFoundException":
            raise


def _create_cluster(ctx) -> str:
    ecs = ctx.client("ecs")
    name = ctx.unique_name("sim2real-behav-cl-")
    cluster_arn = ecs.create_cluster(clusterName=name)["cluster"]["clusterArn"]
    ctx.on_cleanup(lambda: _safe(lambda: ecs.delete_cluster(cluster=cluster_arn)))
    return cluster_arn


def _register_container_instance(ctx, cluster_arn: str, doc: str, sig: str) -> str:
    ecs = ctx.client("ecs")
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


def _instance_profile_visible(iam, name) -> bool:
    """True once GetInstanceProfile sees the profile; False only on NoSuchEntity (IAM
    propagation lag). Any other error propagates."""
    try:
        iam.get_instance_profile(InstanceProfileName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "NoSuchEntity":
            return False
        raise
    return True


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _launch_identity_source_instance(ctx):
    """Launch an EC2 instance with an SSM-capable profile and fetch its AWS-signed identity
    document and signature via SSM Run Command; returns (document_json, signature).
    Raises AssertionError if a prerequisite (network, IAM/SSM permissions) is unavailable."""
    ec2 = ctx.client("ec2")
    iam = ctx.client("iam")
    ssm = ctx.client("ssm")

    try:
        vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    except ClientError as exc:
        raise AssertionError(f"cannot describe the shared network: {exc}")
    if not vpcs:
        raise AssertionError("no shared network VPC available to launch a real EC2 instance")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    if not subnets:
        raise AssertionError("shared network has no subnets")
    subnet_id = subnets[0]["SubnetId"]

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
    _poll_until(
        lambda: _instance_profile_visible(iam, profile_name),
        lambda visible: visible,
        timeout_s=15.0,
        interval_s=2.0,
    )

    ami_id = ssm.get_parameter(
        Name="/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
    )["Parameter"]["Value"]

    # EC2 can reject a new instance profile ("Invalid IAM Instance Profile name") for tens of
    # seconds after IAM shows it; retry only that error, on a deadline.
    instance_id = None
    last_err = None
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
            code = exc.response.get("Error", {}).get("Code")
            message = exc.response.get("Error", {}).get("Message", "")
            if code == "InvalidParameterValue" and "Invalid IAM Instance Profile" in message:
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

    online = _poll_until(_ssm_ping_status, lambda status: status == "Online", timeout_s=120.0, interval_s=5.0)
    if online != "Online":
        raise AssertionError(f"identity-fetch EC2 instance never registered Online with SSM (status={online!r})")

    # IMDSv2 may be required: a token-less request gets a 401, so fetch a token first.
    command_id = ssm.send_command(
        InstanceIds=[instance_id],
        DocumentName="AWS-RunShellScript",
        Parameters={
            "commands": [
                "TOKEN=$(curl -s -X PUT http://169.254.169.254/latest/api/token "
                "-H 'X-aws-ec2-metadata-token-ttl-seconds: 21600')",
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
        raise AssertionError("identity document/signature retrieval produced empty output")
    return doc_str, sig_str


def _ignore_client_error(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("InvalidInstanceID.NotFound", "NoSuchEntity"):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
