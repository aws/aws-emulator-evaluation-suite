"""container-instance-register-deregister-lifecycle."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "container-instance-register-deregister-lifecycle"
GROUP = "state-machine"
SERVICES = ["ecs"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """RegisterContainerInstance makes it visible in DescribeContainerInstances/ListContainerInstances,
    and DeregisterContainerInstance removes it (subsequent describe returns a MISSING failure)."""
    ecs = ctx.client("ecs")

    cluster_name = ctx.unique_name("sim2real-behav-ci-cluster-")
    cluster_arn = ecs.create_cluster(clusterName=cluster_name)["cluster"]["clusterArn"]
    ctx.on_cleanup(lambda: ecs.delete_cluster(cluster=cluster_arn))

    # Real AWS cryptographically validates the instance identity document/signature pair on
    # RegisterContainerInstance and rejects an omitted (or synthetic) pair with
    # InvalidParameterException ("...were not valid") — leaving both fields out is NOT accepted.
    # Provision a real, running EC2 instance and pull ITS genuine, AWS-signed identity
    # document/signature via SSM Run Command so the registration is actually accepted.
    doc, sig = _launch_identity_source_instance(ctx)
    registered = ecs.register_container_instance(
        cluster=cluster_arn,
        instanceIdentityDocument=doc,
        instanceIdentityDocumentSignature=sig,
        totalResources=[
            {"name": "CPU", "type": "INTEGER", "integerValue": 2048},
            {"name": "MEMORY", "type": "INTEGER", "integerValue": 4096},
            {"name": "PORTS", "type": "STRINGSET", "stringSetValue": []},
        ],
    )["containerInstance"]
    ci_arn = registered["containerInstanceArn"]
    assert registered["status"] in ("ACTIVE", "REGISTERING")

    ctx.on_cleanup(
        lambda: _ignore_client_error(
            lambda: ecs.deregister_container_instance(
                cluster=cluster_arn, containerInstance=ci_arn, force=True
            )
        )
    )

    listed = ecs.list_container_instances(cluster=cluster_arn)["containerInstanceArns"]
    assert ci_arn in listed

    described = ecs.describe_container_instances(cluster=cluster_arn, containerInstances=[ci_arn])
    assert not described["failures"], described["failures"]
    assert described["containerInstances"][0]["containerInstanceArn"] == ci_arn
    assert described["containerInstances"][0]["status"] == "ACTIVE"

    deregistered = ecs.deregister_container_instance(
        cluster=cluster_arn, containerInstance=ci_arn, force=True
    )
    assert deregistered["containerInstance"]["containerInstanceArn"] == ci_arn

    # DeregisterContainerInstance does not erase the record: it survives as an independently
    # readable INACTIVE container instance (confirmed against real AWS — a bare "gone with a
    # MISSING failure" guess does not hold), and only drops out of the default active listing.
    after = ecs.describe_container_instances(cluster=cluster_arn, containerInstances=[ci_arn])
    assert not after["failures"], after["failures"]
    assert after["containerInstances"][0]["containerInstanceArn"] == ci_arn
    assert after["containerInstances"][0]["status"] == "INACTIVE", after["containerInstances"][0]["status"]

    remaining = ecs.list_container_instances(cluster=cluster_arn)["containerInstanceArns"]
    assert ci_arn not in remaining

    # A mutation on the now-INACTIVE id must also fail, not just a read: it is dead for
    # scheduling purposes even though it is still describable.
    mutated = ecs.update_container_instances_state(
        cluster=cluster_arn, containerInstances=[ci_arn], status="DRAINING"
    )
    assert mutated["containerInstances"] == [], mutated["containerInstances"]
    assert mutated["failures"], "expected a failure mutating the deregistered (INACTIVE) instance"
    # UpdateContainerInstancesState's failures[].arn comes back short-form (no cluster segment)
    # even when Register/DescribeContainerInstances return the long form for the same instance
    # on this account — compare by container-instance id, not full ARN equality.
    assert mutated["failures"][0]["arn"].rsplit("/", 1)[-1] == ci_arn.rsplit("/", 1)[-1], mutated["failures"][0]
    assert mutated["failures"][0]["reason"] == "INACTIVE", mutated["failures"][0]


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


def _visible(fn) -> bool:
    """Whether fn() finds the resource: NoSuchEntity is not yet, any other error raises."""
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
        return False
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
    """Launch a genuine EC2 instance behind an SSM-capable instance profile and pull ITS real,
    AWS-signed instance-identity document + signature via SSM Run Command. Returns
    (identity_document_json, identity_document_signature). Registers cleanup for every resource it
    creates; raises AssertionError if a prerequisite (shared network, IAM/SSM permissions) isn't
    available in this account."""
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
        lambda: _visible(lambda: iam.get_instance_profile(InstanceProfileName=profile_name)),
        lambda seen: seen,
        timeout_s=15.0,
        interval_s=2.0,
    )

    ami_id = ssm.get_parameter(
        Name="/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
    )["Parameter"]["Value"]

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
            code = exc.response["Error"]["Code"]
            # IAM's own get_instance_profile going green (above) does not mean EC2's control
            # plane has caught up yet; that propagation gap is a separate, longer window.
            if code in ("InvalidParameterValue", "InvalidParameterCombination") and "profile" in str(exc).lower():
                time.sleep(5.0)
                continue
            raise
    if instance_id is None:
        raise AssertionError(f"could not launch the identity-fetch EC2 instance: {last_err}")
    ctx.on_cleanup(lambda: _ignore_client_error(lambda: ec2.terminate_instances(InstanceIds=[instance_id])))

    def _instance_state():
        # DescribeInstances can return InvalidInstanceID.NotFound for a few seconds right after
        # RunInstances returns, before the instance is visible; that is not the same as the
        # instance being gone.
        try:
            return ec2.describe_instances(InstanceIds=[instance_id])["Reservations"][0]["Instances"][0][
                "State"
            ]["Name"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "InvalidInstanceID.NotFound":
                return "pending-visibility"
            raise

    _poll_until(_instance_state, lambda state: state == "running", timeout_s=45.0, interval_s=5.0)

    def _ssm_ping_status():
        info = ssm.describe_instance_information(Filters=[{"Key": "InstanceIds", "Values": [instance_id]}])[
            "InstanceInformationList"
        ]
        return info[0]["PingStatus"] if info else None

    online = _poll_until(_ssm_ping_status, lambda status: status == "Online", timeout_s=120.0, interval_s=5.0)
    if online != "Online":
        raise AssertionError(f"identity-fetch EC2 instance never registered Online with SSM (status={online!r})")

    command_id = ssm.send_command(
        InstanceIds=[instance_id],
        DocumentName="AWS-RunShellScript",
        Parameters={
            "commands": [
                # IMDSv2 (token-gated) is the account default for freshly launched instances;
                # an unauthenticated IMDSv1 GET silently returns nothing rather than erroring.
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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
