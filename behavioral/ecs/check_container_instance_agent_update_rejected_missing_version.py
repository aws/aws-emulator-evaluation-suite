"""container-instance-agent-update-rejected-missing-version."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "container-instance-agent-update-rejected-missing-version"
GROUP = "state-machine"
SERVICES = ["ecs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateContainerAgent on a container instance registered without agent versionInfo fails with
    MissingVersionException ("Unknown current version") and leaves agentUpdateStatus unchanged."""
    ecs = ctx.client("ecs")

    cluster_name = ctx.unique_name("sim2real-behav-agent-cluster-")
    cluster_arn = ecs.create_cluster(clusterName=cluster_name)["cluster"]["clusterArn"]
    ctx.on_cleanup(lambda: ecs.delete_cluster(cluster=cluster_arn))

    # RegisterContainerInstance rejects an omitted or synthetic identity document/signature, so a
    # real instance supplies a genuine signed pair; versionInfo is deliberately omitted.
    (subject_identity,) = _launch_identity_source_instances(ctx, count=1)

    registered = ecs.register_container_instance(
        cluster=cluster_arn,
        instanceIdentityDocument=subject_identity[0],
        instanceIdentityDocumentSignature=subject_identity[1],
        totalResources=[{"name": "CPU", "type": "INTEGER", "integerValue": 1024}],
    )["containerInstance"]
    ci_arn = registered["containerInstanceArn"]
    ctx.on_cleanup(
        lambda: _ignore_client_error(
            lambda: ecs.deregister_container_instance(
                cluster=cluster_arn, containerInstance=ci_arn, force=True
            )
        )
    )
    before_status = registered.get("agentUpdateStatus")

    code, message = _error(
        lambda: ecs.update_container_agent(cluster=cluster_arn, containerInstance=ci_arn)
    )
    assert code == "MissingVersionException", f"expected MissingVersionException, got {code}"
    expected_message = "Unknown current version"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    described = ecs.describe_container_instances(cluster=cluster_arn, containerInstances=[ci_arn])
    after_status = described["containerInstances"][0].get("agentUpdateStatus")
    assert after_status == before_status, (
        f"agentUpdateStatus should not have transitioned on a rejected update: "
        f"before={before_status!r} after={after_status!r}"
    )


def _error(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _instance_profile_visible(iam, profile_name):
    try:
        iam.get_instance_profile(InstanceProfileName=profile_name)
    except ClientError:
        return False
    return True


def _ignore_client_error(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "ClusterNotFoundException",
            "InvalidInstanceID.NotFound",
            "NoSuchEntity",
        ):
            raise


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _launch_identity_source_instances(ctx, count):
    """Launch `count` EC2 instances with an SSM-capable profile and return each one's signed
    (identity_document, signature) pair, read via SSM Run Command."""
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

    # Instance-profile propagation into EC2 lags IAM's own visibility, so retry to a deadline.
    instance_ids = None
    last_err = None
    deadline = time.monotonic() + 90.0
    while time.monotonic() < deadline:
        try:
            reservation = ec2.run_instances(
                ImageId=ami_id,
                InstanceType="t3.micro",
                MinCount=count,
                MaxCount=count,
                SubnetId=subnet_id,
                IamInstanceProfile={"Name": profile_name},
                TagSpecifications=[
                    {
                        "ResourceType": "instance",
                        "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-ci-identity-")}],
                    }
                ],
            )
            instance_ids = [i["InstanceId"] for i in reservation["Instances"]]
            break
        except ClientError as exc:
            last_err = exc
            time.sleep(5.0)
    if instance_ids is None:
        raise AssertionError(f"could not launch the identity-fetch EC2 instances: {last_err}")
    ctx.on_cleanup(lambda: _ignore_client_error(lambda: ec2.terminate_instances(InstanceIds=instance_ids)))

    def _all_running():
        # A just-launched instance id can trail RunInstances' own response by a couple of
        # seconds before DescribeInstances will resolve it — a transient NotFound here means
        # "not visible yet", not "gone".
        try:
            instances = ec2.describe_instances(InstanceIds=instance_ids)["Reservations"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "InvalidInstanceID.NotFound":
                return []
            raise
        states = [i["State"]["Name"] for r in instances for i in r["Instances"]]
        return states

    _poll_until(
        _all_running,
        lambda states: len(states) == count and all(s == "running" for s in states),
        timeout_s=60.0,
        interval_s=5.0,
    )

    def _online_ids():
        info = ssm.describe_instance_information(Filters=[{"Key": "InstanceIds", "Values": instance_ids}])[
            "InstanceInformationList"
        ]
        return {i["InstanceId"] for i in info if i.get("PingStatus") == "Online"}

    online = _poll_until(
        _online_ids, lambda ids: len(ids) == count, timeout_s=180.0, interval_s=5.0
    )
    if len(online) != count:
        raise AssertionError(f"not every identity-fetch EC2 instance registered Online with SSM: {online!r}")

    # IMDSv2 token required — an account/AMI with instance-metadata-defaults set to
    # HttpTokens=required answers an unauthenticated (IMDSv1-style) curl with an empty 401 body.
    script = (
        "TOKEN=$(curl -s -X PUT http://169.254.169.254/latest/api/token "
        "-H 'X-aws-ec2-metadata-token-ttl-seconds: 21600'); "
        "curl -s -H \"X-aws-ec2-metadata-token: $TOKEN\" "
        "http://169.254.169.254/latest/dynamic/instance-identity/document; "
        "echo SIM2REAL_SPLIT; "
        "curl -s -H \"X-aws-ec2-metadata-token: $TOKEN\" "
        "http://169.254.169.254/latest/dynamic/instance-identity/signature"
    )
    command_id = ssm.send_command(
        InstanceIds=instance_ids,
        DocumentName="AWS-RunShellScript",
        Parameters={"commands": [script]},
    )["Command"]["CommandId"]

    identities = []
    for instance_id in instance_ids:

        def _invocation(iid=instance_id):
            try:
                return ssm.get_command_invocation(CommandId=command_id, InstanceId=iid)
            except ClientError:
                return {"Status": "Pending"}

        invocation = _poll_until(
            _invocation,
            lambda inv: inv.get("Status") in ("Success", "Failed", "Cancelled", "TimedOut"),
            timeout_s=30.0,
            interval_s=3.0,
        )
        if invocation.get("Status") != "Success":
            raise AssertionError(
                f"identity-document SSM command did not succeed on {instance_id}: {invocation.get('Status')!r}"
            )

        doc_str, _, sig_str = invocation["StandardOutputContent"].partition("SIM2REAL_SPLIT")
        doc_str = doc_str.strip()
        sig_str = sig_str.strip()
        if not doc_str or not sig_str:
            raise AssertionError(f"identity document/signature retrieval produced empty output on {instance_id}")
        identities.append((doc_str, sig_str))

    return identities


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
