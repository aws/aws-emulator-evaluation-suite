"""attributes-put-list-delete-lifecycle."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "attributes-put-list-delete-lifecycle"
GROUP = "state-machine"
SERVICES = ["ecs"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutAttributes makes a custom attribute visible via ListAttributes, and DeleteAttributes
    removes it again."""
    ecs = ctx.client("ecs")

    cluster_name = ctx.unique_name("sim2real-behav-attr-cluster-")
    cluster_arn = ecs.create_cluster(clusterName=cluster_name)["cluster"]["clusterArn"]
    ctx.on_cleanup(lambda: ecs.delete_cluster(cluster=cluster_arn))

    # Real AWS cryptographically validates the instance identity document/signature pair on
    # RegisterContainerInstance and rejects an omitted (or synthetic) pair with
    # InvalidParameterException ("...were not valid") — leaving both fields out is NOT accepted
    # the way a manual/external-style registration might assume. Provision a real, running EC2
    # instance and pull ITS genuine, AWS-signed identity document/signature via SSM Run Command so
    # the registration is actually accepted.
    doc, sig = _launch_identity_source_instance(ctx)
    ci_arn = ecs.register_container_instance(
        cluster=cluster_arn,
        instanceIdentityDocument=doc,
        instanceIdentityDocumentSignature=sig,
        totalResources=[{"name": "CPU", "type": "INTEGER", "integerValue": 1024}],
    )["containerInstance"]["containerInstanceArn"]
    ctx.on_cleanup(
        lambda: _ignore_client_error(
            lambda: ecs.deregister_container_instance(
                cluster=cluster_arn, containerInstance=ci_arn, force=True
            )
        )
    )

    attr_name = "sim2real.behav-attr"
    attr_value = "v1"

    baseline = ecs.list_attributes(
        cluster=cluster_arn, targetType="container-instance", attributeName=attr_name
    )["attributes"]
    baseline_matches = [a for a in baseline if a["targetId"] == ci_arn]
    assert not baseline_matches, f"expected no attribute before PutAttributes, got {baseline_matches!r}"

    ecs.put_attributes(
        cluster=cluster_arn,
        attributes=[{"name": attr_name, "value": attr_value, "targetId": ci_arn}],
    )
    ctx.on_cleanup(
        lambda: _ignore_client_error(
            lambda: ecs.delete_attributes(
                cluster=cluster_arn,
                # DeleteAttributes' own contract: for a custom attribute, specify name + targetId
                # and omit value — the API rejects a value on delete with InvalidParameterException.
                attributes=[{"name": attr_name, "targetId": ci_arn}],
            )
        )
    )

    def _listed():
        return ecs.list_attributes(
            cluster=cluster_arn, targetType="container-instance", attributeName=attr_name
        )["attributes"]

    # ListAttributes is eventually consistent right after PutAttributes.
    listed = _poll_until(
        _listed,
        lambda rows: any(a["targetId"] == ci_arn for a in rows),
        timeout_s=30.0,
        interval_s=2.0,
    )
    matches = [a for a in listed if a["targetId"] == ci_arn and a["value"] == attr_value]
    assert len(matches) == 1, f"expected exactly one matching attribute, got {listed!r}"

    ecs.delete_attributes(
        cluster=cluster_arn,
        attributes=[{"name": attr_name, "targetId": ci_arn}],
    )

    after = _poll_until(
        _listed,
        lambda rows: not any(a["targetId"] == ci_arn for a in rows),
        timeout_s=30.0,
        interval_s=2.0,
    )
    assert not [a for a in after if a["targetId"] == ci_arn], f"attribute still present: {after!r}"


def _ignore_client_error(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "ClusterNotFoundException",
            "InvalidInstanceID.NotFound",
            "NoSuchEntity",
            "TargetNotFoundException",
        ):
            raise


def _succeeds(fn) -> bool:
    """True when fn() returns, False when it raises a ClientError."""
    try:
        fn()
    except ClientError:
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
    (identity_document_json, identity_document_signature). Registers cleanup for every resource
    it creates; raises AssertionError (a hard failure, never a skip) if a prerequisite (default
    VPC, IAM/SSM permissions) isn't available in this account."""
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
        lambda visible: visible,
        timeout_s=15.0,
        interval_s=2.0,
    )

    ami_id = ssm.get_parameter(
        Name="/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
    )["Parameter"]["Value"]

    # A successful iam.get_instance_profile above proves IAM's own control plane has the
    # profile, but EC2 syncs IAM state on a separate, slower path — RunInstances can keep
    # answering InvalidParameterValue ("Invalid IAM Instance Profile name") for well past that
    # point. Retry on exactly that propagation-lag error for a bounded window; any other error
    # is a real failure and must not be retried away.
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
            code = exc.response["Error"].get("Code")
            message = exc.response["Error"].get("Message", "")
            propagating = (f"Value ({profile_name}) for parameter iamInstanceProfile.name is invalid. "
                           "Invalid IAM Instance Profile name")
            if code != "InvalidParameterValue" or message != propagating:
                raise AssertionError(f"could not launch the identity-fetch EC2 instance: {exc}") from exc
            time.sleep(5.0)
    if instance_id is None:
        raise AssertionError(
            f"identity-fetch EC2 instance never launched within 90s of IAM/EC2 instance-profile "
            f"propagation retries: {last_err}"
        )
    ctx.on_cleanup(lambda: _ignore_client_error(lambda: ec2.terminate_instances(InstanceIds=[instance_id])))

    # RunInstances returning an instance id is no guarantee DescribeInstances can already see
    # it — EC2's own eventual consistency answers InvalidInstanceID.NotFound for a few seconds
    # right after launch. Treat that specific error as "not visible yet", not a hard failure.
    def _instance_state():
        try:
            reservations = ec2.describe_instances(InstanceIds=[instance_id])["Reservations"]
        except ClientError as exc:
            if exc.response["Error"].get("Code") == "InvalidInstanceID.NotFound":
                return None
            raise
        if not reservations:
            return None
        return reservations[0]["Instances"][0]["State"]["Name"]

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
            # AL2023 AMIs default to IMDSv2 (HttpTokens: required) — an unauthenticated GET
            # against the metadata service returns no body, so fetch a token first.
            "commands": [
                'TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" '
                '-H "X-aws-ec2-metadata-token-ttl-seconds: 60")',
                'curl -s -H "X-aws-ec2-metadata-token: $TOKEN" '
                "http://169.254.169.254/latest/dynamic/instance-identity/document",
                "echo SIM2REAL_SPLIT",
                'curl -s -H "X-aws-ec2-metadata-token: $TOKEN" '
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
