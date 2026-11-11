"""create-association-duplicate-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-association-duplicate-rejected"
GROUP = "state-machine"
SERVICES = ["ssm"]

_AL2023_AMI_PARAM = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"


@tags("axis:rejection", "cap:c2", "cap:c3", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateAssociation for the same document+targets combination twice is rejected
    with AssociationAlreadyExists, and the original association is left untouched."""
    ssm = ctx.client("ssm")
    doc_name = _create_command_document(ctx)
    # On real AWS, the "Targets"-based CreateAssociation surface deliberately
    # *allows* creating multiple associations for the same document+targets
    # combination (this is the "multiple associations per target" feature, used
    # e.g. to run the same document on the same targets on different schedules).
    # The AssociationAlreadyExists duplicate rejection only applies to the
    # legacy single-instance "InstanceId" parameter, which predates that
    # feature and still enforces a single association per document+instance.
    #
    # The legacy InstanceId parameter is validated against a *real* instance
    # (CreateAssociation raises InvalidInstanceId for a well-formed but
    # nonexistent/unregistered instance ID), so this needs an actual,
    # currently-registered SSM managed instance — provision one rather than
    # depending on one already existing in the account.
    instance_id = _provision_managed_instance(ctx)

    original = ssm.create_association(Name=doc_name, InstanceId=instance_id)["AssociationDescription"]
    assoc_id = original["AssociationId"]
    ctx.on_cleanup(lambda: _delete_association_if_exists(ssm, assoc_id))

    # The duplicate-association check performed by CreateAssociation is backed by an
    # eventually-consistent index of the just-created association: a duplicate attempt
    # fired immediately afterwards can race ahead of that index update and briefly
    # succeed (minting an unwanted second association) instead of being rejected.
    # Retry, cleaning up any such stray association, until the index has caught up and
    # the expected AssociationAlreadyExists rejection is observed.
    code = message = None
    for _ in range(15):
        try:
            stray = ssm.create_association(Name=doc_name, InstanceId=instance_id)["AssociationDescription"]
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            message = exc.response["Error"].get("Message")
            if code == "AssociationAlreadyExists":
                break
            raise
        else:
            stray_id = stray["AssociationId"]
            ctx.on_cleanup(lambda sid=stray_id: _delete_association_if_exists(ssm, sid))
            _delete_association_if_exists(ssm, stray_id)
            code = None
            time.sleep(2.0)
    assert code == "AssociationAlreadyExists", code
    # AWS answers this refusal with an empty message.
    assert message == "", f"CreateAssociation message: {message!r}"

    # Positive control: the original association is untouched (still version "1",
    # same AssociationId) and no second association was created for this document.
    described = ssm.describe_association(AssociationId=assoc_id)["AssociationDescription"]
    assert described["AssociationId"] == assoc_id
    assert described["AssociationVersion"] == "1"

    all_ids = set()
    next_token = None
    for _ in range(50):
        kwargs = {"NextToken": next_token} if next_token else {}
        page = ssm.list_associations(**kwargs)
        for a in page.get("Associations", []):
            if a.get("Name") == doc_name:
                all_ids.add(a["AssociationId"])
        next_token = page.get("NextToken")
        if not next_token:
            break
    assert all_ids == {assoc_id}, all_ids


def _create_command_document(ctx) -> str:
    ssm = ctx.client("ssm")
    name = ctx.unique_name("sim2real-ssm-doc-")
    # CreateAssociation's legacy InstanceId parameter rejects schema 2.2+ documents with
    # InvalidDocument ("not supported by association that is created with instance id") —
    # confirmed on real AWS. It needs the older 1.2 runtimeConfig document shape, which
    # predates the Targets-based association surface this InstanceId path is legacy for.
    content = json.dumps(
        {
            "schemaVersion": "1.2",
            "description": "sim2real behavioral test document",
            "runtimeConfig": {
                "aws:runShellScript": {
                    "properties": [
                        {"id": "0.aws:runShellScript", "runCommand": ["echo sim2real"]}
                    ]
                }
            },
        }
    )
    ssm.create_document(
        Content=content,
        Name=name,
        DocumentType="Command",
        DocumentFormat="JSON",
        Tags=[{"Key": "Name", "Value": name}],
    )
    ctx.on_cleanup(lambda: ssm.delete_document(Name=name, Force=True))
    return name


def _provision_managed_instance(ctx) -> str:
    """Launch a real EC2 instance with the AmazonSSMManagedInstanceCore role and
    wait for it to register Online with SSM, so the legacy InstanceId
    CreateAssociation path has a real, currently-registered instance to validate against."""
    instance_profile = _ssm_instance_profile(ctx)
    ami_id = _latest_al2023_ami(ctx)
    instance_id = _launch_instance(ctx, ami_id, instance_profile)
    info = _wait_ssm_online(ctx, instance_id, timeout_s=600.0)
    if info is None:
        raise AssertionError(f"instance {instance_id} never registered Online with SSM")
    return instance_id


def _latest_al2023_ami(ctx) -> str:
    ssm = ctx.client("ssm")
    return ssm.get_parameter(Name=_AL2023_AMI_PARAM)["Parameter"]["Value"]


def _default_subnet(ctx) -> str:
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available to launch a test EC2 instance")
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpcs[0]["VpcId"]]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    if not subnets:
        raise AssertionError("shared network has no subnets available")
    return subnets[0]["SubnetId"]


def _ssm_instance_profile(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-ssm-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    profile_name = ctx.unique_name("sim2real-ssm-profile-")
    iam.create_instance_profile(InstanceProfileName=profile_name)
    ctx.on_cleanup(lambda: iam.delete_instance_profile(InstanceProfileName=profile_name))
    iam.add_role_to_instance_profile(InstanceProfileName=profile_name, RoleName=role_name)
    ctx.on_cleanup(
        lambda: iam.remove_role_from_instance_profile(InstanceProfileName=profile_name, RoleName=role_name)
    )
    deadline = time.monotonic() + 30.0
    while time.monotonic() < deadline:
        try:
            iam.get_instance_profile(InstanceProfileName=profile_name)
            break
        except ClientError:
            time.sleep(2.0)
    return profile_name


def _launch_instance(ctx, ami_id: str, instance_profile_name: str) -> str:
    ec2 = ctx.client("ec2")
    subnet_id = _default_subnet(ctx)
    name = ctx.unique_name("sim2real-assoc-dup-")
    kwargs = dict(
        ImageId=ami_id,
        InstanceType="t3.micro",
        MinCount=1,
        MaxCount=1,
        SubnetId=subnet_id,
        IamInstanceProfile={"Name": instance_profile_name},
        TagSpecifications=[{"ResourceType": "instance", "Tags": [{"Key": "Name", "Value": name}]}],
    )
    # A freshly created IAM instance profile can take longer to propagate to the EC2
    # control plane than to IAM itself; retry RunInstances on that specific error.
    deadline = time.monotonic() + 60.0
    while True:
        try:
            resp = ec2.run_instances(**kwargs)
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "InvalidParameterValue" and time.monotonic() < deadline:
                time.sleep(5.0)
                continue
            raise
    instance_id = resp["Instances"][0]["InstanceId"]
    ctx.on_cleanup(lambda: ec2.terminate_instances(InstanceIds=[instance_id]))
    ec2.get_waiter("instance_running").wait(InstanceIds=[instance_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    return instance_id


def _wait_ssm_online(ctx, instance_id: str, timeout_s: float = 300.0, interval_s: float = 10.0):
    ssm = ctx.client("ssm")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = ssm.describe_instance_information(Filters=[{"Key": "InstanceIds", "Values": [instance_id]}])
        items = resp.get("InstanceInformationList", [])
        if items and items[0].get("PingStatus") == "Online":
            return items[0]
        time.sleep(interval_s)
    return None


def _delete_association_if_exists(ssm, assoc_id: str) -> None:
    try:
        ssm.delete_association(AssociationId=assoc_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "AssociationDoesNotExist":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
