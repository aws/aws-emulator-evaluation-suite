"""update-association-status-transitions-and-nonexistent-rejected."""
from __future__ import annotations

import json
import time
from datetime import datetime, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-association-status-transitions-and-nonexistent-rejected"
GROUP = "state-machine"
SERVICES = ["ssm"]

_DOC_NAME = "AWS-UpdateSSMAgent"
_UNRELATED_DOC_NAME = "AWS-RunShellScript"
# Fires only on Feb 29 (leap years) -- effectively never during a test run -- so the
# association never auto-applies out from under our manual UpdateAssociationStatus calls.
_FAR_FUTURE_CRON = "cron(0 0 29 2 ? *)"
_AMI_PARAM = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
_SSM_CORE_POLICY_ARN = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateAssociationStatus drives a legacy InstanceId-created association's Status.Name
    through Success/Failed/Pending, and is rejected with AssociationDoesNotExist for a real
    managed node that was never associated with a given document name."""
    ssm = ctx.client("ssm")
    instance_id = _provision_connected_target(ctx)
    doc_name = _create_legacy_document(ctx)

    created = ssm.create_association(
        Name=doc_name,
        InstanceId=instance_id,
        # NOTE: ScheduleExpression/ApplyOnlyAtCronInterval/DocumentVersion/OutputLocation/
        # AssociationName are not supported together with the legacy InstanceId parameter --
        # AWS rejects the combination with ValidationException. The association runs
        # immediately on create, but each UpdateAssociationStatus call below is synchronous
        # and its response reflects that exact write regardless of any concurrent agent-driven
        # run.
    )
    actual_instance_id = created["AssociationDescription"]["InstanceId"]
    assert actual_instance_id == instance_id, (
        f"expected CreateAssociation to bind InstanceId {instance_id!r}, "
        f"got {actual_instance_id!r}"
    )
    ctx.on_cleanup(
        lambda: ssm.delete_association(Name=doc_name, InstanceId=instance_id)
    )

    # CreateAssociation's legacy-InstanceId write path has a brief propagation lag before
    # UpdateAssociationStatus's separate lookup path can see the new association -- poll
    # DescribeAssociation (bounded) rather than assuming immediate consistency.
    _poll_until(
        lambda: _association_visible(ssm, doc_name, instance_id),
        lambda visible: visible,
        timeout_s=_budget_s(ctx, 60.0),
        interval_s=2.0,
    )

    for target_status in ("Success", "Failed", "Pending"):
        resp = _retry_until_visible(
            ctx,
            lambda: ssm.update_association_status(
                Name=doc_name,
                InstanceId=instance_id,
                AssociationStatus={
                    "Date": datetime.now(timezone.utc),
                    "Name": target_status,
                    "Message": f"sim2real-behav transition to {target_status}",
                },
            )
        )
        actual = resp["AssociationDescription"]["Status"]["Name"]
        assert actual == target_status, (
            f"expected status {target_status!r} after update, got {actual!r}"
        )

    # Negative: the same real, registered managed node, but a document name it was never
    # associated with -- rejected with AssociationDoesNotExist (not InvalidInstanceId, since
    # the instance itself is perfectly valid).
    code, message = _expect_rejected(
        lambda: ssm.update_association_status(
            Name=_UNRELATED_DOC_NAME,
            InstanceId=instance_id,
            AssociationStatus={
                "Date": datetime.now(timezone.utc),
                "Name": "Success",
                "Message": "sim2real-behav negative probe",
            },
        )
    )
    assert code == "AssociationDoesNotExist", (
        f"expected AssociationDoesNotExist for a never-associated document, got {code!r}"
    )
    assert message == "", message

    # Effect absent: no association was created between this instance and the unrelated doc.
    code2, message2 = _expect_rejected(
        lambda: ssm.describe_association(Name=_UNRELATED_DOC_NAME, InstanceId=instance_id)
    )
    assert code2 == "AssociationDoesNotExist", (
        f"expected no association to exist for ({_UNRELATED_DOC_NAME}, {instance_id}) after "
        f"the rejected update, got {code2!r}"
    )
    assert message2 == (
        f"Association not found for documentName {_UNRELATED_DOC_NAME} and instanceId "
        f"{instance_id}. Try using the association-id parameter if you are looking for an "
        "association created using targets."
    ), message2


def _association_visible(ssm, doc_name, instance_id) -> bool:
    """True once DescribeAssociation resolves the (Name, InstanceId) pair; a propagating
    association reads as AssociationDoesNotExist, and any other error raises."""
    try:
        ssm.describe_association(Name=doc_name, InstanceId=instance_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "AssociationDoesNotExist":
            raise
        return False
    return True


def _expect_rejected(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response["Error"]
        return error["Code"], error.get("Message", "")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while time.monotonic() < deadline:
        if predicate(value):
            return value
        time.sleep(interval_s)
        value = probe()
    return value


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _wait_running(ec2, instance_ids, timeout_s: float, ctx=None) -> None:
    """Poll every 2 s until every instance is running; fails on a dead-end state or the deadline."""
    deadline = time.monotonic() + timeout_s
    states = {}
    while True:
        try:
            reservations = ec2.describe_instances(InstanceIds=list(instance_ids))["Reservations"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidInstanceID.NotFound":
                raise
            reservations = []
        states = {i["InstanceId"]: i["State"]["Name"] for r in reservations for i in r["Instances"]}
        if len(states) == len(instance_ids) and all(s == "running" for s in states.values()):
            return
        assert not any(s in ("shutting-down", "terminated", "stopping", "stopped") for s in states.values()), (
            f"instances {list(instance_ids)} reached {states!r} instead of running")
        if time.monotonic() >= deadline and ctx is not None and _budget_spent(ctx):
            raise TimeoutError("instances reaching running: the run budget ended first; not graded")
        assert time.monotonic() < deadline, (
            f"instances {list(instance_ids)} not running in time: {states!r}")
        time.sleep(2.0)


def _retry_until_visible(ctx, fn):
    """Retry a call that can transiently see AssociationDoesNotExist while the just-created
    association is still propagating to UpdateAssociationStatus's lookup path."""
    deadline = time.monotonic() + _budget_s(ctx, 60.0)
    last_err = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AssociationDoesNotExist":
                raise
            last_err = exc
            time.sleep(2)
    if _budget_spent(ctx):
        raise TimeoutError("the association becoming visible: the run budget ended first; not graded")
    raise AssertionError(f"association never became visible to UpdateAssociationStatus: {last_err}")


def _create_legacy_document(ctx) -> str:
    """AWS-owned documents (e.g. AWS-UpdateSSMAgent) have been migrated to a schema version
    that CreateAssociation's legacy InstanceId path rejects with InvalidDocument. Author our
    own minimal schema-1.2 Command document (the schema legacy InstanceId associations
    support) so the InstanceId path can be exercised at all."""
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
    ssm.create_document(
        Name=doc_name,
        Content=content,
        DocumentType="Command",
        DocumentFormat="JSON",
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ssm.delete_document(Name=doc_name))
    return doc_name



def _default_subnet_id(ec2, *, ctx):
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        return None
    subnets = ec2.describe_subnets(
        Filters=[
            {"Name": "vpc-id", "Values": [vpcs[0]["VpcId"]]},
            {"Name": "subnet-id", "Values": ctx.network().subnet_ids},
        ]
    )["Subnets"]
    return subnets[0]["SubnetId"] if subnets else None


def _provision_connected_target(ctx) -> str:
    """Create an IAM role + instance profile with AmazonSSMManagedInstanceCore, launch one EC2
    instance, and wait until it registers Online with Systems Manager. Returns its InstanceId."""
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

    subnet_id = _default_subnet_id(ec2, ctx=ctx)
    if not subnet_id:
        raise AssertionError(
            "no default VPC/subnet available to launch a test managed-instance EC2 host"
        )

    ami_id = ssm.get_parameter(Name=_AMI_PARAM)["Parameter"]["Value"]
    name_tag = ctx.unique_name("sim2real-behav-ssm-target-")

    instance_ids: list[str] = []
    last_err = None
    deadline = time.monotonic() + _budget_s(ctx, 90.0)
    while not instance_ids and time.monotonic() < deadline:
        try:
            run_resp = ec2.run_instances(
                ImageId=ami_id,
                InstanceType="t3.micro",
                MinCount=1,
                MaxCount=1,
                SubnetId=subnet_id,
                IamInstanceProfile={"Name": profile_name},
                TagSpecifications=[
                    {"ResourceType": "instance", "Tags": [{"Key": "Name", "Value": name_tag}]}
                ],
            )
            instance_ids = [i["InstanceId"] for i in run_resp["Instances"]]
        except ClientError as exc:
            last_err = exc
            if exc.response["Error"]["Code"] not in (
                "InvalidParameterValue",
                "InvalidParameterValueError",
            ):
                raise
            time.sleep(2)
    if not instance_ids:
        if _budget_spent(ctx):
            raise TimeoutError("RunInstances accepting the instance profile: the run budget ended first; "
                               "not graded")
        raise AssertionError(f"run_instances never succeeded after IAM propagation: {last_err}")
    ctx.on_cleanup(lambda: ec2.terminate_instances(InstanceIds=instance_ids))

    _wait_running(ec2, instance_ids, _budget_s(ctx, 600.0), ctx=ctx)

    deadline = time.monotonic() + _budget_s(ctx, 600.0)
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
        if _budget_spent(ctx):
            raise TimeoutError(f"instances {pending} reaching PingStatus=Online: the run budget ended first; "
                               "not graded")
        raise AssertionError(f"instances {pending} never reached SSM PingStatus=Online in time")
    return instance_ids[0]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
