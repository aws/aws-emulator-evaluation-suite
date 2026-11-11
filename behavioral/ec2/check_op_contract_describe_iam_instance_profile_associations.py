"""op-contract-describe-iam-instance-profile-associations."""
from __future__ import annotations

import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-describe-iam-instance-profile-associations"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeIamInstanceProfileAssociations shows a launched instance's profile as associated and
    finds it by AssociationIds; an unknown filter name is rejected (InvalidParameterValue)."""
    ec2 = ctx.client("ec2")
    ami_id = _find_al2023_ami(ctx)
    profile = _create_instance_profile(ctx)
    instance_id = _launch_instance(
        ctx,
        ami_id,
        extra_kwargs={"IamInstanceProfile": {"Name": profile["name"]}},
    )

    association = _poll_until(
        lambda: ec2.describe_iam_instance_profile_associations(
            Filters=[{"Name": "instance-id", "Values": [instance_id]}]
        )["IamInstanceProfileAssociations"],
        lambda assocs: bool(assocs) and assocs[0]["State"] == "associated",
        timeout_s=90.0,
        interval_s=3.0,
    )[0]
    assert association["InstanceId"] == instance_id, (
        f"expected InstanceId {instance_id}, got {association['InstanceId']}"
    )
    assert association["IamInstanceProfile"]["Arn"] == profile["arn"], (
        f"expected profile arn {profile['arn']}, got {association['IamInstanceProfile']['Arn']}"
    )
    assoc_id = association["AssociationId"]

    by_id = ec2.describe_iam_instance_profile_associations(AssociationIds=[assoc_id])[
        "IamInstanceProfileAssociations"
    ]
    assert len(by_id) == 1 and by_id[0]["AssociationId"] == assoc_id, (
        f"expected exactly one association {assoc_id}, got {by_id}"
    )

    code, message = _error(
        lambda: ec2.describe_iam_instance_profile_associations(
            Filters=[{"Name": "sim2real-bogus-filter", "Values": ["x"]}]
        )
    )
    assert code == "InvalidParameterValue", f"expected InvalidParameterValue, got {code}"
    expected = "An unknown filter 'sim2real-bogus-filter' was given"
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _error(fn):
    """Return fn()'s (code, message); a success raises, never reading as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err["Message"]
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


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
    import json

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
    return {"name": profile_name, "arn": arn}


def _launch_instance(ctx, ami_id: str, instance_type: str = "t3.micro", extra_kwargs: dict | None = None) -> str:

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
    if extra_kwargs:
        kwargs.update(extra_kwargs)

    last_exc = None
    resp = None
    for _ in range(8):
        try:
            resp = ec2.run_instances(**kwargs)
            break
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in ("VPCIdNotSpecified", "MissingInput"):
                raise AssertionError(f"cannot launch instance: {code}")
            # A new instance profile is not usable by RunInstances until IAM propagates.
            if code == "InvalidParameterValue" and "Invalid IAM Instance Profile" in str(exc):
                last_exc = exc
                time.sleep(5)
                continue
            raise
    if resp is None:
        raise last_exc  # type: ignore[misc]

    instance_id = resp["Instances"][0]["InstanceId"]
    ctx.on_cleanup(lambda: ec2.terminate_instances(InstanceIds=[instance_id]))
    waiter = ec2.get_waiter("instance_running")
    waiter.wait(InstanceIds=[instance_id], WaiterConfig={"Delay": 2, "MaxAttempts": 100})
    return instance_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
