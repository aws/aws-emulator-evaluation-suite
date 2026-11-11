"""register-container-instance-malformed-identity-document-rejected."""
from __future__ import annotations

import json
import time
from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "register-container-instance-malformed-identity-document-rejected"
GROUP = "negative-classes"
SERVICES = ["ecs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """RegisterContainerInstance with a malformed or missing identity document is rejected.

    A genuine AWS-signed document registers, proving the call can succeed on this cluster.
    """
    ecs = ctx.client("ecs")

    cluster_arn = ecs.create_cluster(
        clusterName=ctx.unique_name("sim2real-behav-cluster-"),
        tags=[{"key": "sim2real-check", "value": CHECK}],
    )["cluster"]["clusterArn"]
    ctx.on_cleanup(lambda: ecs.delete_cluster(cluster=cluster_arn))

    # Positive control: a genuine, AWS-signed identity document/signature pair IS accepted.
    doc, sig = _launch_identity_source_instance(ctx)
    registered = ecs.register_container_instance(
        cluster=cluster_arn,
        instanceIdentityDocument=doc,
        instanceIdentityDocumentSignature=sig,
        totalResources=[
            {"name": "CPU", "type": "INTEGER", "integerValue": 1024},
            {"name": "MEMORY", "type": "INTEGER", "integerValue": 2048},
            {"name": "PORTS", "type": "STRINGSET", "stringSetValue": []},
            {"name": "PORTS_UDP", "type": "STRINGSET", "stringSetValue": []},
        ],
    )["containerInstance"]
    ci_arn = registered["containerInstanceArn"]
    assert registered["status"] in ("ACTIVE", "REGISTERING"), (
        f"expected a genuine identity document to register successfully, got status {registered['status']!r}"
    )
    ctx.on_cleanup(
        lambda: _ignore_client_error(
            lambda: ecs.deregister_container_instance(cluster=cluster_arn, containerInstance=ci_arn, force=True)
        )
    )

    before = set(ecs.list_container_instances(cluster=cluster_arn)["containerInstanceArns"])
    assert ci_arn in before, "the genuinely-signed registration must be visible in ListContainerInstances"

    # Negative: an unsigned, malformed identity document/signature pair.
    code, message = _error(
        lambda: ecs.register_container_instance(
            cluster=cluster_arn,
            instanceIdentityDocument="not-a-valid-instance-identity-document",
            instanceIdentityDocumentSignature="not-a-valid-signature",
        )
    )
    assert code == "InvalidParameterException", (
        f"expected InvalidParameterException for a malformed identity document, got {code!r}"
    )
    assert message == "An identity document was provided, but not valid.", message

    # Effect absent: no additional container instance was registered from the malformed attempt.
    after = set(ecs.list_container_instances(cluster=cluster_arn)["containerInstanceArns"])
    assert after == before, "malformed identity document must not register a container instance"

    # Omitting the document entirely is also refused with InvalidParameterException.
    bare_code, bare_message = _error(lambda: ecs.register_container_instance(cluster=cluster_arn))
    assert bare_code == "InvalidParameterException", (
        f"expected InvalidParameterException for a missing identity document, got {bare_code!r}"
    )
    assert bare_message == "The identity document and identity document signature were not valid.", bare_message

    after2 = set(ecs.list_container_instances(cluster=cluster_arn)["containerInstanceArns"])
    assert after2 == before, "an instance must not be registered without a valid identity document"


def _error(fn: Callable[[], Any]) -> tuple[str, str]:
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected success
    raises, because an emulator accepting input real AWS refuses must fail loudly rather than
    read as an error-code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response["Error"]
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _ignore_client_error(fn: Callable[[], Any]) -> None:
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


def _launch_identity_source_instance(ctx):
    """Launch a genuine EC2 instance behind an SSM-capable instance profile and pull ITS real,
    AWS-signed instance-identity document + signature via SSM Run Command. Returns
    (identity_document_json, identity_document_signature). Registers cleanup for every resource
    it creates."""
    ec2 = ctx.client("ec2")
    iam = ctx.client("iam")
    ssm = ctx.client("ssm")

    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available to launch a real EC2 instance")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    if not subnets:
        raise AssertionError("shared network has no subnets")
    subnet_id = subnets[0]["SubnetId"]

    role_name = ctx.unique_name("sim2real-rcimid-role-")
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
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
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
        except ClientError:
            return False
        return True

    _poll_until(_profile_visible, lambda visible: visible, timeout_s=15.0, interval_s=2.0)

    ami_id = ssm.get_parameter(
        Name="/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
    )["Parameter"]["Value"]

    instance_id = None
    last_err = None
    for _attempt in range(6):
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
                        "Tags": [
                            {"Key": "Name", "Value": ctx.unique_name("sim2real-rcimid-")},
                            {"Key": "sim2real-check", "Value": CHECK},
                        ],
                    }
                ],
            )
            instance_id = reservation["Instances"][0]["InstanceId"]
            break
        except ClientError as exc:
            last_err = exc
            time.sleep(5.0)
    if instance_id is None:
        raise AssertionError(f"could not launch the identity-fetch EC2 instance: {last_err}")
    ctx.on_cleanup(lambda: _ignore_client_error(lambda: ec2.terminate_instances(InstanceIds=[instance_id])))

    def _instance_state():
        try:
            return ec2.describe_instances(InstanceIds=[instance_id])["Reservations"][0]["Instances"][0]["State"][
                "Name"
            ]
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "InvalidInstanceID.NotFound":
                return "pending-visibility"
            raise

    _poll_until(_instance_state, lambda state: state == "running", timeout_s=60.0, interval_s=5.0)

    def _ssm_ping_status():
        info = ssm.describe_instance_information(Filters=[{"Key": "InstanceIds", "Values": [instance_id]}])[
            "InstanceInformationList"
        ]
        return info[0]["PingStatus"] if info else None

    online = _poll_until(_ssm_ping_status, lambda status: status == "Online", timeout_s=180.0, interval_s=5.0)
    if online != "Online":
        raise AssertionError(f"identity-fetch EC2 instance never registered Online with SSM (status={online!r})")

    command_id = ssm.send_command(
        InstanceIds=[instance_id],
        DocumentName="AWS-RunShellScript",
        Parameters={
            "commands": [
                "TOKEN=$(curl -s -X PUT http://169.254.169.254/latest/api/token"
                " -H 'X-aws-ec2-metadata-token-ttl-seconds: 21600')",
                "curl -s -H \"X-aws-ec2-metadata-token: $TOKEN\""
                " http://169.254.169.254/latest/dynamic/instance-identity/document",
                "echo SIM2REAL_SPLIT",
                "curl -s -H \"X-aws-ec2-metadata-token: $TOKEN\""
                " http://169.254.169.254/latest/dynamic/instance-identity/signature",
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
