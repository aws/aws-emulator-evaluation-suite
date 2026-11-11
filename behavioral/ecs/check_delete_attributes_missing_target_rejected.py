"""delete-attributes-missing-target-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "delete-attributes-missing-target-rejected"
GROUP = "state-machine"
SERVICES = ["ecs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteAttributes on a deregistered container instance is rejected with
    TargetNotFoundException and changes nothing, while the same call on the still-registered
    instance succeeds and removes the attribute."""
    ecs = ctx.client("ecs")

    cluster_name = ctx.unique_name("sim2real-behav-attr-missing-cluster-")
    cluster_arn = ecs.create_cluster(clusterName=cluster_name)["cluster"]["clusterArn"]
    ctx.on_cleanup(lambda: ecs.delete_cluster(cluster=cluster_arn))

    # A never-registered ARN does not reliably reach the target-exists check, so a real
    # instance is registered and then deregistered. RegisterContainerInstance rejects a
    # synthetic identity document/signature pair, so a real one is fetched.
    doc, sig = _launch_identity_source_instance(ctx)
    registered = ecs.register_container_instance(
        cluster=cluster_arn,
        instanceIdentityDocument=doc,
        instanceIdentityDocumentSignature=sig,
        totalResources=[{"name": "CPU", "type": "INTEGER", "integerValue": 1024}],
    )["containerInstance"]
    target_arn = registered["containerInstanceArn"]

    # Positive control while the target is still live.
    control_attr = ctx.unique_name("sim2real.control-attr-")
    ecs.put_attributes(
        cluster=cluster_arn,
        attributes=[{"name": control_attr, "value": "v1", "targetId": target_arn}],
    )
    ecs.delete_attributes(
        cluster=cluster_arn,
        attributes=[{"name": control_attr, "targetId": target_arn}],
    )
    # ListAttributes is eventually consistent with DeleteAttributes; poll for the removal.
    _poll_until(
        lambda: ecs.list_attributes(
            cluster=cluster_arn, targetType="container-instance", attributeName=control_attr
        )["attributes"],
        lambda attrs: attrs == [],
        timeout_s=30.0,
        interval_s=2.0,
    )

    ecs.deregister_container_instance(cluster=cluster_arn, containerInstance=target_arn, force=True)

    missing_attr = ctx.unique_name("sim2real.no-such-attr-")
    code, message = _expect_error(
        lambda: ecs.delete_attributes(
            cluster=cluster_arn,
            attributes=[{"name": missing_attr, "targetId": target_arn}],
        )
    )
    assert code == "TargetNotFoundException", f"expected TargetNotFoundException, got {code}"
    instance_id = target_arn.rsplit("/", 1)[-1]
    assert message == f"Container instance {instance_id} is inactive.", (
        f"expected the exact missing-target message, got {message!r}"
    )

    # Independent read at the destination: the rejected call left no visible trace either.
    listed = ecs.list_attributes(
        cluster=cluster_arn, targetType="container-instance", attributeName=missing_attr
    )["attributes"]
    assert listed == [], f"rejected DeleteAttributes still produced a visible attribute: {listed}"


def _succeeds(fn) -> bool:
    """True when fn() returns, False when it raises a ClientError (a readiness probe)."""
    try:
        fn()
    except ClientError:
        return False
    return True


def _expect_error(fn):
    """The error code and message of a call that must be rejected; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call succeeded: {result!r}")


def _ignore_client_error(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("InvalidInstanceID.NotFound", "NoSuchEntity"):
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


def _launch_identity_source_instance(ctx):
    """Launch an EC2 instance and fetch its signed identity document via SSM Run Command.
    Returns (identity_document_json, identity_document_signature)."""
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
        lambda: _succeeds(lambda: iam.get_instance_profile(InstanceProfileName=profile_name)),
        lambda ready: ready,
        timeout_s=15.0,
        interval_s=2.0,
    )

    ami_id = ssm.get_parameter(
        Name="/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
    )["Parameter"]["Value"]

    instance_id = None
    last_err = None
    run_deadline = time.monotonic() + 90.0
    while time.monotonic() < run_deadline:
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
            # A freshly-created instance profile isn't immediately usable by EC2 (IAM->EC2
            # propagation lag) -- retry only that specific, known-transient shape.
            if code in ("InvalidParameterValue", "InvalidParameterCombination") and "profile" in str(exc).lower():
                time.sleep(5.0)
                continue
            raise AssertionError(f"could not launch the identity-fetch EC2 instance: {exc}")
    if instance_id is None:
        raise AssertionError(f"could not launch the identity-fetch EC2 instance: {last_err}")
    ctx.on_cleanup(lambda: _ignore_client_error(lambda: ec2.terminate_instances(InstanceIds=[instance_id])))

    def _instance_state():
        # Immediately after run_instances returns, DescribeInstances can still raise
        # InvalidInstanceID.NotFound for a brief eventual-consistency window before the new
        # instance is visible. Treat that as "not running yet" rather than a hard failure.
        try:
            return ec2.describe_instances(InstanceIds=[instance_id])["Reservations"][0]["Instances"][0]["State"][
                "Name"
            ]
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "InvalidInstanceID.NotFound":
                return "pending-visibility"
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

    # Default IMDS settings may enforce IMDSv2: an untokened GET returns 401, which curl -s
    # turns into empty output. Fetch a token first.
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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
