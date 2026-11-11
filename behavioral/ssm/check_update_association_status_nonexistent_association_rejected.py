"""update-association-status-nonexistent-association-rejected."""
from __future__ import annotations

import json
import time
from datetime import datetime, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-association-status-nonexistent-association-rejected"
GROUP = "overly-permissive"
SERVICES = ["ssm"]

_AMI_PARAM = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
_SSM_CORE_POLICY_ARN = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateAssociationStatus on a Name/InstanceId pair whose association was already deleted
    returns AssociationDoesNotExist rather than silently accepting the status update, while
    updating the status of a still-live association still succeeds."""
    ssm = ctx.client("ssm")
    instance_id = _provision_connected_target(ctx)
    doc_name = _create_legacy_document(ctx)

    ssm.create_association(Name=doc_name, InstanceId=instance_id)
    ctx.on_cleanup(lambda: _best_effort_delete(ssm, doc_name, instance_id))

    # positive control: updating the status of the live association succeeds and persists.
    # CreateAssociation's legacy-InstanceId write path has a brief propagation lag before
    # UpdateAssociationStatus's separate lookup path can see the new association, so the first
    # control update is retried (bounded) rather than assumed immediately consistent.
    _retry_until_visible(
        lambda: ssm.update_association_status(
            Name=doc_name,
            InstanceId=instance_id,
            AssociationStatus={
                "Date": datetime.now(timezone.utc),
                "Name": "Success",
                "Message": "sim2real control update",
            },
        )
    )
    described = ssm.describe_association(Name=doc_name, InstanceId=instance_id)
    actual = described["AssociationDescription"]["Status"]["Name"]
    assert actual == "Success", f"expected Status.Name Success after control update, got {actual!r}"

    # break exactly one thing: delete the association, then try to update its status
    ssm.delete_association(Name=doc_name, InstanceId=instance_id)

    code, message = _error(
        lambda: ssm.update_association_status(
            Name=doc_name,
            InstanceId=instance_id,
            AssociationStatus={
                "Date": datetime.now(timezone.utc),
                "Name": "Success",
                "Message": "should not apply",
            },
        )
    )
    assert code == "AssociationDoesNotExist", code
    assert message == "", message

    # effect absent: the association wasn't silently recreated by the failed update
    code2, message2 = _error(
        lambda: ssm.describe_association(Name=doc_name, InstanceId=instance_id)
    )
    assert code2 == "AssociationDoesNotExist", code2
    assert message2 == (
        f"Association not found for documentName {doc_name} and instanceId {instance_id}. "
        "Try using the association-id parameter if you are looking for an association created "
        "using targets."
    ), message2


# ===== helpers =====


def _error(fn):
    """Call fn(); return its error (code, message). An unexpected SUCCESS raises, because
    accepting input AWS refuses must fail loudly, not as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response["Error"]
        return error["Code"], error.get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _retry_until_visible(fn):
    """Retry a call that can transiently see AssociationDoesNotExist while the just-created
    association is still propagating to UpdateAssociationStatus's lookup path."""
    deadline = time.monotonic() + 60.0
    last_err = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AssociationDoesNotExist":
                raise
            last_err = exc
            time.sleep(3)
    raise AssertionError(f"association never became visible to UpdateAssociationStatus: {last_err}")


def _create_legacy_document(ctx) -> str:
    """AWS-owned documents (e.g. AWS-RunShellScript) have been migrated to a schema version
    that CreateAssociation's legacy InstanceId path rejects with InvalidDocument. Author our own
    minimal schema-1.2 Command document (the schema legacy InstanceId associations support) so
    the InstanceId path can be exercised at all."""
    ssm = ctx.client("ssm")
    doc_name = ctx.unique_name("sim2real-behav-legacy-doc-")
    content = json.dumps(
        {
            "schemaVersion": "1.2",
            "description": "sim2real-behav legacy (schema 1.2) document for InstanceId "
            "association tests",
            "runtimeConfig": {
                "aws:runShellScript": {
                    "properties": [
                        {"id": "0.aws:runShellScript", "runCommand": ["echo sim2real-behav"]}
                    ]
                }
            },
        }
    )
    ssm.create_document(Name=doc_name, Content=content, DocumentType="Command", DocumentFormat="JSON")
    ctx.on_cleanup(lambda: ssm.delete_document(Name=doc_name))
    return doc_name


def _provision_connected_target(ctx) -> str:
    """Create an IAM role + instance profile with AmazonSSMManagedInstanceCore, launch one EC2
    instance, and wait until it registers Online with Systems Manager. Returns its InstanceId.
    UpdateAssociationStatus's legacy InstanceId surface validates the instance against a real,
    currently-registered SSM managed node (a fabricated InstanceId is rejected immediately with
    InvalidInstanceId), so this environment's boundary can only be exercised against one."""
    iam = ctx.client("iam")
    ec2 = ctx.client("ec2")
    ssm = ctx.client("ssm")

    role_name = ctx.unique_name("sim2real-behav-ssm-role-")
    trust_policy = json.dumps(
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
    )
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=trust_policy)
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.attach_role_policy(RoleName=role_name, PolicyArn=_SSM_CORE_POLICY_ARN)
    ctx.on_cleanup(
        lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=_SSM_CORE_POLICY_ARN)
    )

    profile_name = ctx.unique_name("sim2real-behav-ssm-profile-")
    iam.create_instance_profile(InstanceProfileName=profile_name)
    ctx.on_cleanup(lambda: iam.delete_instance_profile(InstanceProfileName=profile_name))
    iam.add_role_to_instance_profile(InstanceProfileName=profile_name, RoleName=role_name)
    ctx.on_cleanup(
        lambda: iam.remove_role_from_instance_profile(
            InstanceProfileName=profile_name, RoleName=role_name
        )
    )

    ami_id = ssm.get_parameter(Name=_AMI_PARAM)["Parameter"]["Value"]
    name_tag = ctx.unique_name("sim2real-behav-ssm-target-")

    instance_ids: list[str] = []
    last_err = None
    deadline = time.monotonic() + 90
    while not instance_ids and time.monotonic() < deadline:
        try:
            run_resp = ec2.run_instances(
                ImageId=ami_id,
                InstanceType="t3.micro",
                MinCount=1,
                MaxCount=1,
                IamInstanceProfile={"Name": profile_name},
                TagSpecifications=[
                    {"ResourceType": "instance", "Tags": [{"Key": "Name", "Value": name_tag}]}
                ],
                SubnetId=ctx.network().subnet_ids[0],
            )
            instance_ids = [i["InstanceId"] for i in run_resp["Instances"]]
        except ClientError as exc:
            last_err = exc
            if exc.response["Error"]["Code"] not in (
                "InvalidParameterValue",
                "InvalidParameterValueError",
            ):
                raise
            time.sleep(5)
    if not instance_ids:
        raise AssertionError(f"run_instances never succeeded after IAM propagation: {last_err}")
    ctx.on_cleanup(lambda: ec2.terminate_instances(InstanceIds=instance_ids))

    ec2.get_waiter("instance_running").wait(InstanceIds=instance_ids, WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    deadline = time.monotonic() + 600
    pending = set(instance_ids)
    while pending and time.monotonic() < deadline:
        info = ssm.describe_instance_information(
            Filters=[{"Key": "InstanceIds", "Values": list(pending)}]
        )["InstanceInformationList"]
        online = {i["InstanceId"] for i in info if i.get("PingStatus") == "Online"}
        pending -= online
        if pending:
            time.sleep(2)
    if pending:
        raise AssertionError(f"instances {pending} never reached SSM PingStatus=Online in time")
    return instance_ids[0]


def _best_effort_delete(ssm, doc_name: str, instance_id: str) -> None:
    try:
        ssm.delete_association(Name=doc_name, InstanceId=instance_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "AssociationDoesNotExist":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
