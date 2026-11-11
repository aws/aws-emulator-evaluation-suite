"""associate-second-iam-instance-profile-rejected."""
from __future__ import annotations

import json
import time
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "associate-second-iam-instance-profile-rejected"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A second AssociateIamInstanceProfile on an instance that has one is refused with IncorrectState and its exact
    message and the original stays the only association; after it is disassociated, the same call associates
    the second profile.
    """
    ec2 = ctx.client("ec2")
    ami_id = _find_al2023_ami(ctx)
    profile_a = _create_instance_profile(ctx)
    profile_b = _create_instance_profile(ctx)
    instance_id = _launch_instance(ctx, ami_id)

    first = _associate_with_retry(ec2, instance_id, profile_a["name"])
    first_assoc_id = first["AssociationId"]
    assert first["State"] in ("associating", "associated"), (
        f"expected associating|associated on create, got {first['State']!r}"
    )

    def _association_state(assoc_id):
        # Right after creation an AssociationIds lookup can answer InvalidAssociationID.NotFound, so that
        # code, like an empty result, means "not visible yet".
        try:
            assocs = ec2.describe_iam_instance_profile_associations(AssociationIds=[assoc_id])[
                "IamInstanceProfileAssociations"
            ]
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "InvalidAssociationID.NotFound":
                return None
            raise
        return assocs[0]["State"] if assocs else None

    _poll_until(
        lambda: _association_state(first_assoc_id),
        lambda state: state == "associated",
        timeout_s=60.0,
        interval_s=3.0,
    )

    # Attempting a second association on the same instance must be rejected outright.
    code, code_message = _error_code(
        lambda: ec2.associate_iam_instance_profile(
            IamInstanceProfile={"Name": profile_b["name"]}, InstanceId=instance_id
        )
    )
    assert code == "IncorrectState", f"expected IncorrectState for a duplicate association, got {code}"
    expected_code_message = f"There is an existing association for instance {instance_id}"
    assert code_message == expected_code_message, f"expected message {expected_code_message!r}, got {code_message!r}"

    # The original association must remain the sole association for this instance.
    associations = ec2.describe_iam_instance_profile_associations(
        Filters=[{"Name": "instance-id", "Values": [instance_id]}]
    )["IamInstanceProfileAssociations"]
    active = [a for a in associations if a["State"] != "disassociated"]
    assert len(active) == 1 and active[0]["AssociationId"] == first_assoc_id, (
        f"expected only {first_assoc_id} active, got {[a['AssociationId'] for a in active]}"
    )
    assert active[0]["IamInstanceProfile"]["Arn"] == profile_a["arn"], (
        f"expected profile {profile_a['arn']}, got {active[0]['IamInstanceProfile']['Arn']}"
    )

    # Restore: disassociate the original, then the same associate of profile_b must succeed. A
    # disassociated id answers InvalidAssociationID.NotFound to an AssociationIds lookup, so the wait
    # reads the instance's active associations.
    def _active_association_ids():
        assocs = ec2.describe_iam_instance_profile_associations(
            Filters=[{"Name": "instance-id", "Values": [instance_id]}]
        )["IamInstanceProfileAssociations"]
        return [a["AssociationId"] for a in assocs if a["State"] != "disassociated"]

    ec2.disassociate_iam_instance_profile(AssociationId=first_assoc_id)
    _poll_until(
        _active_association_ids,
        lambda ids: first_assoc_id not in ids,
        timeout_s=60.0,
        interval_s=3.0,
    )

    second = _associate_with_retry(ec2, instance_id, profile_b["name"])
    second_assoc_id = second["AssociationId"]
    ctx.on_cleanup(lambda: ec2.disassociate_iam_instance_profile(AssociationId=second_assoc_id))
    assert second["State"] in ("associating", "associated"), (
        f"expected associating|associated on the restored call, got {second['State']!r}"
    )
    _poll_until(
        lambda: _association_state(second_assoc_id),
        lambda state: state == "associated",
        timeout_s=60.0,
        interval_s=3.0,
    )

    restored = ec2.describe_iam_instance_profile_associations(
        Filters=[{"Name": "instance-id", "Values": [instance_id]}]
    )["IamInstanceProfileAssociations"]
    restored_active = [a for a in restored if a["State"] != "disassociated"]
    assert len(restored_active) == 1 and restored_active[0]["AssociationId"] == second_assoc_id, (
        f"expected only {second_assoc_id} active after restore, "
        f"got {[a['AssociationId'] for a in restored_active]}"
    )
    assert restored_active[0]["IamInstanceProfile"]["Arn"] == profile_b["arn"], (
        f"expected profile {profile_b['arn']} after restore, "
        f"got {restored_active[0]['IamInstanceProfile']['Arn']}"
    )


def _error_code(fn: Callable[[], Any]) -> tuple[str, str | None]:
    """Call fn() and return its (code, message); a call that succeeds raises."""
    try:
        result = fn()
    except Exception as exc:
        err = getattr(exc, "response", {}).get("Error")
        if not err:
            raise
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last}")


def _find_al2023_ami(ctx) -> str:
    ec2 = ctx.client("ec2")
    resp = ec2.describe_images(
        Owners=["amazon"],
        Filters=[
            {"Name": "name", "Values": ["al2023-ami-*-x86_64"]},
            {"Name": "state", "Values": ["available"]},
        ],
    )
    images = resp.get("Images", [])
    if not images:
        raise AssertionError("no amazon-owned al2023 AMI visible in this account/region")
    images.sort(key=lambda i: i.get("CreationDate", ""), reverse=True)
    return images[0]["ImageId"]


def _create_instance_profile(ctx) -> dict[str, str]:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-ec2role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    profile_name = ctx.unique_name("sim2real-ec2prof-")
    created = iam.create_instance_profile(InstanceProfileName=profile_name)
    arn = created["InstanceProfile"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_instance_profile(InstanceProfileName=profile_name))

    iam.add_role_to_instance_profile(InstanceProfileName=profile_name, RoleName=role_name)
    ctx.on_cleanup(
        lambda: iam.remove_role_from_instance_profile(InstanceProfileName=profile_name, RoleName=role_name)
    )

    for _ in range(20):
        prof = iam.get_instance_profile(InstanceProfileName=profile_name)
        if prof["InstanceProfile"]["Roles"]:
            break
        time.sleep(1)
    else:
        raise AssertionError(f"role {role_name} never appeared on instance profile {profile_name}")
    return {"name": profile_name, "arn": arn}


def _launch_instance(ctx, ami_id: str, instance_type: str = "t3.micro") -> str:
    ec2 = ctx.client("ec2")
    kwargs: dict[str, Any] = dict(
        ImageId=ami_id,
        InstanceType=instance_type,
        MinCount=1,
        MaxCount=1,
        TagSpecifications=[
            {
                "ResourceType": "instance",
                "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-ec2-")}],
            }
        ],
    )
    try:
        resp = ec2.run_instances(**kwargs)
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        if code in ("VPCIdNotSpecified", "MissingInput"):
            raise AssertionError(f"cannot launch instance: {code}")
        raise

    instance_id = resp["Instances"][0]["InstanceId"]
    ctx.on_cleanup(lambda: ec2.terminate_instances(InstanceIds=[instance_id]))
    waiter = ec2.get_waiter("instance_running")
    waiter.wait(InstanceIds=[instance_id], WaiterConfig={"Delay": 2, "MaxAttempts": 100})
    return instance_id


def _associate_with_retry(ec2, instance_id: str, profile_name: str, attempts: int = 8, delay: float = 5.0):
    last_exc = None
    for _ in range(attempts):
        try:
            return ec2.associate_iam_instance_profile(
                IamInstanceProfile={"Name": profile_name}, InstanceId=instance_id
            )["IamInstanceProfileAssociation"]
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "InvalidParameterValue" and "Invalid IAM Instance Profile" in str(exc):
                last_exc = exc
                time.sleep(delay)
                continue
            raise
    raise last_exc  # type: ignore[misc]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
