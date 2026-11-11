"""delete-inventory-invalid-parameters-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-inventory-invalid-parameters-rejected"
GROUP = "overly-permissive"
SERVICES = ["ssm"]

_AMI_PARAM = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
_SSM_CORE_POLICY_ARN = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"

# The 900 s ssm cleanup budget minus a margin, one deadline shared by every teardown of a run.
_TEARDOWN_S = 840.0


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:ssm-custom-inventory-schemas")
def run(ctx) -> None:
    """DeleteInventory with DryRun and SchemaDeleteOption=DeleteSchema on a registered custom type
    answers with a preview naming that TypeName and a DeletionSummary, and the schema stays
    registered: a dry run must never delete or disable the schema."""

    ssm = ctx.client("ssm")

    teardown_deadline: dict = {}
    instance_id = _provision_managed_instance(ctx, teardown_deadline)

    type_name = f"Custom:{ctx.unique_name('sim2realInvDel').replace('-', '')}"
    ssm.put_inventory(
        InstanceId=instance_id,
        Items=[
            {
                "TypeName": type_name,
                "SchemaVersion": "1.0",
                "CaptureTime": _now().strftime("%Y-%m-%dT%H:%M:%SZ"),
                "Content": [{"Attribute": "Value"}],
            }
        ],
    )
    def _cleanup_delete():
        try:
            ssm.delete_inventory(TypeName=type_name, SchemaDeleteOption="DeleteSchema")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidTypeNameException":
                raise
        # DeleteSchema completes asynchronously and can take over 10 minutes; wait until the schema is gone.
        _poll_until(
            lambda: _schema_exists(ssm, type_name),
            lambda exists: not exists,
            timeout_s=_remaining(teardown_deadline),
            interval_s=2.0,
        )

    ctx.on_cleanup(_cleanup_delete)

    # PutInventory's own 200 does not mean the schema is yet visible to other operations --
    # DeleteInventory/GetInventorySchema can still answer InvalidTypeNameException for a beat
    # after a successful Put. Wait for the schema to actually register before treating it as
    # "a genuinely-registered custom schema".
    _poll_until(
        lambda: _schema_exists(ssm, type_name),
        lambda exists: exists,
        timeout_s=90.0,
        interval_s=3.0,
    )

    # Positive control: a plain DryRun DATA preview (no SchemaDeleteOption) for the registered
    # custom type succeeds and reports what would be deleted.
    preview = ssm.delete_inventory(TypeName=type_name, DryRun=True)
    assert preview["TypeName"] == type_name, (
        f"DryRun-only preview returned TypeName {preview.get('TypeName')!r}, expected {type_name!r}"
    )

    # DryRun with SchemaDeleteOption previews the schema delete without performing it.
    schema_preview = ssm.delete_inventory(TypeName=type_name, SchemaDeleteOption="DeleteSchema", DryRun=True)
    assert schema_preview["TypeName"] == type_name, (
        f"DryRun schema-delete preview returned TypeName {schema_preview.get('TypeName')!r}, "
        f"expected {type_name!r}"
    )
    assert "DeletionSummary" in schema_preview, (
        f"DryRun schema-delete preview carries no DeletionSummary: {schema_preview!r}"
    )

    # Effect absent: the schema is still registered after both previews.
    schemas = ssm.get_inventory_schema(TypeName=type_name).get("Schemas", [])
    assert any(s["TypeName"] == type_name for s in schemas), (
        "the custom schema disappeared after a DryRun DeleteInventory call"
    )


def _now():
    import datetime

    return datetime.datetime.now(datetime.timezone.utc)


def _provision_managed_instance(ctx, teardown_deadline) -> str:
    """Launch a t3.micro EC2 instance with an SSM-managed-instance IAM profile and wait for
    it to register with SSM (PingStatus=Online). Returns the InstanceId. Registers teardown
    for the instance, instance profile and IAM role."""

    ec2 = ctx.client("ec2")
    iam = ctx.client("iam")
    ssm = ctx.client("ssm")

    subnet_id = ctx.network().subnet_ids[0]

    role_name = ctx.unique_name("sim2real-invdel-role-")[:64]
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

    profile_name = ctx.unique_name("sim2real-invdel-profile-")[:128]
    iam.create_instance_profile(InstanceProfileName=profile_name)
    ctx.on_cleanup(lambda: iam.delete_instance_profile(InstanceProfileName=profile_name))
    iam.add_role_to_instance_profile(InstanceProfileName=profile_name, RoleName=role_name)
    ctx.on_cleanup(
        lambda: iam.remove_role_from_instance_profile(
            InstanceProfileName=profile_name, RoleName=role_name
        )
    )

    ami_id = ssm.get_parameter(Name=_AMI_PARAM)["Parameter"]["Value"]
    tag_name = ctx.unique_name("sim2real-invdel-node-")

    instance_id = _retry_on_profile_propagation(
        lambda: ec2.run_instances(
            ImageId=ami_id,
            InstanceType="t3.micro",
            MinCount=1,
            MaxCount=1,
            SubnetId=subnet_id,
            IamInstanceProfile={"Name": profile_name},
            TagSpecifications=[
                {"ResourceType": "instance", "Tags": [{"Key": "Name", "Value": tag_name}]}
            ],
        )["Instances"][0]["InstanceId"]
    )
    def _terminate_instance():
        ec2.terminate_instances(InstanceIds=[instance_id])
        ec2.get_waiter("instance_terminated").wait(
            InstanceIds=[instance_id],
            WaiterConfig={"Delay": 1, "MaxAttempts": max(1, int(_remaining(teardown_deadline)))},
        )

    ctx.on_cleanup(_terminate_instance)

    ec2.get_waiter("instance_running").wait(
        InstanceIds=[instance_id], WaiterConfig={"Delay": 1, "MaxAttempts": 600}
    )

    _poll_until(
        lambda: _ping_status(ssm, instance_id),
        lambda status: status == "Online",
        timeout_s=480.0,
        interval_s=10.0,
    )
    return instance_id


def _ping_status(ssm, instance_id):
    page = ssm.describe_instance_information(
        Filters=[{"Key": "InstanceIds", "Values": [instance_id]}]
    )
    infos = page.get("InstanceInformationList", [])
    return infos[0].get("PingStatus") if infos else None


def _schema_exists(ssm, type_name):
    try:
        result = ssm.get_inventory_schema(TypeName=type_name)
    except ClientError as err:
        if err.response["Error"]["Code"] == "InvalidTypeNameException":
            return False
        raise
    return any(s["TypeName"] == type_name for s in result.get("Schemas", []))


def _remaining(teardown_deadline) -> float:
    """Seconds left on the run's shared teardown deadline, started by the first teardown that asks."""
    deadline = teardown_deadline.setdefault("t", time.monotonic() + _TEARDOWN_S)
    return max(0.0, deadline - time.monotonic())


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last={last!r}")


def _retry_on_profile_propagation(fn, timeout_s: float = 90.0, interval_s: float = 5.0):
    deadline = time.monotonic() + timeout_s
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as err:
            code = err.response["Error"]["Code"]
            msg = err.response["Error"].get("Message", "").lower()
            if code == "InvalidParameterValue" and "invalid iam instance profile" in msg:
                last_err = err
                time.sleep(interval_s)
                continue
            raise
    raise last_err


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
