"""attribute-put-list-delete-roundtrip."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "attribute-put-list-delete-roundtrip"
GROUP = "state-machine"
SERVICES = ["ecs"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutAttributes attaches a custom attribute to a container instance that's visible via
    ListAttributes; DeleteAttributes removes it so it no longer appears."""
    ecs = ctx.client("ecs")

    cluster_arn = ecs.create_cluster(
        clusterName=ctx.unique_name("sim2real-ecs-"),
        tags=[{"key": "sim2real-check", "value": CHECK}],
    )["cluster"]["clusterArn"]
    ctx.on_cleanup(lambda: ecs.delete_cluster(cluster=cluster_arn))

    doc, sig = _launch_identity_source_instance(ctx)
    registered = ecs.register_container_instance(
        cluster=cluster_arn,
        instanceIdentityDocument=doc,
        instanceIdentityDocumentSignature=sig,
        totalResources=[
            {"name": "CPU", "type": "INTEGER", "integerValue": 1024},
            {"name": "MEMORY", "type": "INTEGER", "integerValue": 2048},
        ],
    )
    ci_arn = registered["containerInstance"]["containerInstanceArn"]
    ctx.on_cleanup(lambda: _ignore_client_error(lambda: ecs.deregister_container_instance(
        cluster=cluster_arn, containerInstance=ci_arn, force=True
    )))

    attr_name = "sim2real.fidelity.role"
    attr_value = "canary"

    def _matching_attrs():
        results = []
        token = None
        while True:
            kwargs = {"cluster": cluster_arn, "targetType": "container-instance", "attributeName": attr_name}
            if token:
                kwargs["nextToken"] = token
            page = ecs.list_attributes(**kwargs)
            results.extend(page["attributes"])
            token = page.get("nextToken")
            if not token:
                break
        return results

    def _own_matches():
        return [a for a in _matching_attrs() if a.get("targetId") == ci_arn]

    baseline = _own_matches()
    assert baseline == [], f"attribute already present before PutAttributes: {baseline}"

    ecs.put_attributes(
        cluster=cluster_arn,
        attributes=[{"name": attr_name, "value": attr_value, "targetId": ci_arn, "targetType": "container-instance"}],
    )

    # ListAttributes reads from a store that only converges with PutAttributes eventually, on a
    # container instance this fresh — bound the wait, don't assume the first read is authoritative.
    matches = _poll_until(
        _own_matches,
        lambda m: len(m) == 1,
        timeout_s=30.0,
        interval_s=2.0,
        reason="attribute never appeared via ListAttributes after PutAttributes",
    )
    assert len(matches) == 1, f"expected exactly 1 attribute on {ci_arn}, found {matches}"
    assert matches[0]["value"] == attr_value, f"expected value {attr_value!r}, got {matches[0]!r}"

    # Real AWS rejects a DeleteAttributes request that includes "value" ("Attribute values are
    # not an accepted for this request") -- delete addresses the attribute by name + target only.
    ecs.delete_attributes(
        cluster=cluster_arn,
        attributes=[{"name": attr_name, "targetId": ci_arn, "targetType": "container-instance"}],
    )

    after_delete = _poll_until(
        _own_matches,
        lambda m: m == [],
        timeout_s=30.0,
        interval_s=2.0,
        reason="attribute still present via ListAttributes after DeleteAttributes",
    )
    assert after_delete == [], f"attribute still present after DeleteAttributes: {after_delete}"


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


def _error_code(fn):
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"]
    return None


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0, reason=""):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{reason or 'condition'} not met within {timeout_s}s (last={last!r})")


def _launch_identity_source_instance(ctx):
    """Launch an EC2 instance with an SSM-capable profile and fetch its AWS-signed identity document
    and signature via Run Command, because RegisterContainerInstance rejects a synthetic pair.
    Returns (identity_document_json, identity_document_signature)."""
    ec2 = ctx.client("ec2")
    iam = ctx.client("iam")
    ssm = ctx.client("ssm")

    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    assert vpcs, "no shared network VPC available to launch a real EC2 instance"
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    assert subnets, "shared network has no subnets"
    subnet_id = subnets[0]["SubnetId"]

    role_name = ctx.unique_name("sim2real-attr-ci-role-")
    tag_spec = [{"Key": "sim2real-check", "Value": CHECK}]
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
        Tags=tag_spec,
    )
    ctx.on_cleanup(lambda: _ignore_client_error(lambda: iam.delete_role(RoleName=role_name)))
    ssm_policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=ssm_policy_arn)
    ctx.on_cleanup(
        lambda: _ignore_client_error(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=ssm_policy_arn))
    )
    profile_name = role_name
    iam.create_instance_profile(InstanceProfileName=profile_name, Tags=tag_spec)
    ctx.on_cleanup(lambda: _ignore_client_error(lambda: iam.delete_instance_profile(InstanceProfileName=profile_name)))
    iam.add_role_to_instance_profile(InstanceProfileName=profile_name, RoleName=role_name)
    ctx.on_cleanup(
        lambda: _ignore_client_error(
            lambda: iam.remove_role_from_instance_profile(InstanceProfileName=profile_name, RoleName=role_name)
        )
    )

    # IAM's own store sees the instance profile immediately; EC2's launch path reads from a
    # separate, eventually-consistent replica and can reject it as "Invalid IAM Instance Profile
    # name" well after get_instance_profile already succeeds. Retry RunInstances itself on that
    # specific error rather than trusting the IAM-side read as a sufficient barrier.
    ami_id = ssm.get_parameter(
        Name="/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
    )["Parameter"]["Value"]

    def _try_run_instances():
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
                            {"Key": "Name", "Value": ctx.unique_name("sim2real-attr-ci-identity-")},
                            {"Key": "sim2real-check", "Value": CHECK},
                        ],
                    }
                ],
            )
            return reservation["Instances"][0]["InstanceId"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "InvalidParameterValue" and "Instance Profile" in str(exc):
                return None
            raise

    instance_id = _poll_until(
        _try_run_instances,
        lambda v: v is not None,
        timeout_s=90.0,
        interval_s=5.0,
        reason="RunInstances kept rejecting the freshly created instance profile",
    )
    ctx.on_cleanup(lambda: _ignore_client_error(lambda: ec2.terminate_instances(InstanceIds=[instance_id])))

    def _instance_state():
        try:
            reservations = ec2.describe_instances(InstanceIds=[instance_id])["Reservations"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "InvalidInstanceID.NotFound":
                return None
            raise
        return reservations[0]["Instances"][0]["State"]["Name"] if reservations else None

    _poll_until(
        _instance_state,
        lambda state: state == "running",
        timeout_s=60.0,
        interval_s=5.0,
        reason="identity-fetch EC2 instance never reached running",
    )

    def _ssm_ping_status():
        info = ssm.describe_instance_information(Filters=[{"Key": "InstanceIds", "Values": [instance_id]}])[
            "InstanceInformationList"
        ]
        return info[0]["PingStatus"] if info else None

    _poll_until(
        _ssm_ping_status,
        lambda status: status == "Online",
        timeout_s=100.0,
        interval_s=5.0,
        reason="identity-fetch EC2 instance never registered Online with SSM",
    )

    command_id = ssm.send_command(
        InstanceIds=[instance_id],
        DocumentName="AWS-RunShellScript",
        Parameters={
            "commands": [
                "TOKEN=$(curl -sS -X PUT http://169.254.169.254/latest/api/token -H 'X-aws-ec2-metadata-token-ttl-seconds: 60')",
                "curl -sS -H \"X-aws-ec2-metadata-token: $TOKEN\" http://169.254.169.254/latest/dynamic/instance-identity/document",
                "echo SIM2REAL_SPLIT",
                "curl -sS -H \"X-aws-ec2-metadata-token: $TOKEN\" http://169.254.169.254/latest/dynamic/instance-identity/signature",
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
        reason="identity-document SSM command never finished",
    )
    assert invocation.get("Status") == "Success", (
        f"identity-document SSM command did not succeed: {invocation.get('Status')!r}"
    )

    doc_str, _, sig_str = invocation["StandardOutputContent"].partition("SIM2REAL_SPLIT")
    doc_str = doc_str.strip()
    sig_str = sig_str.strip()
    assert doc_str and sig_str, (
        "identity document/signature retrieval produced empty output: "
        f"stdout={invocation.get('StandardOutputContent')!r} stderr={invocation.get('StandardErrorContent')!r}"
    )
    return doc_str, sig_str


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
