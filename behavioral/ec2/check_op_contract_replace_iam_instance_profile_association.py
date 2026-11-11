"""op-contract-replace-iam-instance-profile-association."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-replace-iam-instance-profile-association"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ReplaceIamInstanceProfileAssociation swaps a running instance's profile from A to B under a
    new association id; a digit-altered AssociationId is rejected with InvalidParameterValue."""
    ec2 = ctx.client("ec2")
    iam = ctx.client("iam")

    trust_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}
            ],
        }
    )

    profile_a_name, role_a_arn = _make_role_and_profile(ctx, iam, "a", trust_policy)
    profile_b_name, role_b_arn = _make_role_and_profile(ctx, iam, "b", trust_policy)

    ami_id = _latest_al2023_ami(ec2)
    instance_id = _run_instance_with_retry(ec2, ami_id, profile_a_name, ctx)
    ctx.on_cleanup(lambda: _terminate_instance(ec2, instance_id))
    ec2.get_waiter("instance_running").wait(InstanceIds=[instance_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    assoc = _poll_until(
        lambda: _find_association(ec2, instance_id),
        lambda a: a is not None,
        timeout_s=60,
        interval_s=3,
    )
    association_id = assoc["AssociationId"]
    assert assoc["IamInstanceProfile"]["Arn"].endswith(f"/{profile_a_name}"), (
        f"expected initial association on profile {profile_a_name!r}, got {assoc['IamInstanceProfile']['Arn']!r}"
    )

    resp = ec2.replace_iam_instance_profile_association(
        AssociationId=association_id, IamInstanceProfile={"Name": profile_b_name}
    )
    new_assoc = resp["IamInstanceProfileAssociation"]
    assert new_assoc["IamInstanceProfile"]["Arn"].endswith(f"/{profile_b_name}"), (
        f"expected profile {profile_b_name!r} after replace, got {new_assoc['IamInstanceProfile']['Arn']!r}"
    )
    assert new_assoc["InstanceId"] == instance_id, (
        f"expected replace to stay on instance {instance_id!r}, got {new_assoc['InstanceId']!r}"
    )
    # Replace mints a new association id rather than mutating the old one in place.
    assert new_assoc["AssociationId"] != association_id, (
        f"expected Replace to mint a new association id, reused {association_id!r}"
    )

    final = _poll_until(
        lambda: ec2.describe_iam_instance_profile_associations(AssociationIds=[new_assoc["AssociationId"]])[
            "IamInstanceProfileAssociations"
        ][0],
        lambda a: a["State"] == "associated",
        timeout_s=60,
        interval_s=3,
    )
    assert final["IamInstanceProfile"]["Arn"].endswith(f"/{profile_b_name}"), (
        f"expected settled association on profile {profile_b_name!r}, got {final['IamInstanceProfile']['Arn']!r}"
    )

    # The operation has no DryRun. A digit-altered AssociationId of the same prefix and length
    # is rejected at parameter validation (InvalidParameterValue), not as NotFound.
    fake_association_id = _mutate_id_suffix(association_id)
    err = _error(
        lambda: ec2.replace_iam_instance_profile_association(
            AssociationId=fake_association_id, IamInstanceProfile={"Name": profile_b_name}
        )
    )
    assert err["Code"] == "InvalidParameterValue", f"unexpected error: {err!r}"
    assert err.get("Message") == f"Invalid Id: {fake_association_id}", (
        f"unexpected message: {err.get('Message')!r}"
    )


def _make_role_and_profile(ctx, iam, suffix, trust_policy):
    role_name = ctx.unique_name(f"sim2real-iprole-{suffix}-")
    profile_name = ctx.unique_name(f"sim2real-ipprof-{suffix}-")
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=trust_policy)["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(iam, role_name))
    iam.create_instance_profile(InstanceProfileName=profile_name)
    ctx.on_cleanup(lambda: _delete_profile(iam, profile_name))
    iam.add_role_to_instance_profile(InstanceProfileName=profile_name, RoleName=role_name)
    return profile_name, role_arn


def _run_instance_with_retry(ec2, ami_id, profile_name, ctx):
    deadline = time.monotonic() + 90
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return ec2.run_instances(
                ImageId=ami_id,
                InstanceType="t3.micro",
                MinCount=1,
                MaxCount=1,
                IamInstanceProfile={"Name": profile_name},
                TagSpecifications=[
                    {"ResourceType": "instance", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-iip-")}]}
                ],
                SubnetId=ctx.network().subnet_ids[0],
            )["Instances"][0]["InstanceId"]
        except ClientError as exc:
            last_exc = exc
            if exc.response["Error"]["Code"] not in ("InvalidParameterValue",):
                raise
            time.sleep(5)
    raise AssertionError(f"instance profile never became usable: {last_exc}")


def _find_association(ec2, instance_id):
    resp = ec2.describe_iam_instance_profile_associations(
        Filters=[{"Name": "instance-id", "Values": [instance_id]}, {"Name": "state", "Values": ["associated"]}]
    )
    assocs = resp.get("IamInstanceProfileAssociations", [])
    return assocs[0] if assocs else None


def _latest_al2023_ami(ec2):
    images = ec2.describe_images(
        Owners=["amazon"],
        Filters=[
            {"Name": "name", "Values": ["al2023-ami-*-x86_64"]},
            {"Name": "state", "Values": ["available"]},
        ],
    )["Images"]
    images.sort(key=lambda i: i["CreationDate"], reverse=True)
    return images[0]["ImageId"]


def _error(fn):
    """Call fn(); return its ClientError Error dict. An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected a ClientError but the call succeeded: {result!r}")


def _mutate_id_suffix(real_id: str) -> str:
    """Shift each hex digit of an id's suffix by one (mod 16).

    The result keeps the prefix, length and charset but differs from the real id."""
    prefix, _, suffix = real_id.rpartition("-")
    shifted = "".join(format((int(c, 16) + 1) % 16, "x") for c in suffix)
    return f"{prefix}-{shifted}"


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last value: {last!r}")


def _terminate_instance(ec2, instance_id):
    try:
        ec2.terminate_instances(InstanceIds=[instance_id])
        ec2.get_waiter("instance_terminated").wait(InstanceIds=[instance_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidInstanceID.NotFound":
            raise


def _delete_profile(iam, profile_name):
    try:
        profile = iam.get_instance_profile(InstanceProfileName=profile_name)["InstanceProfile"]
        for role in profile.get("Roles", []):
            iam.remove_role_from_instance_profile(InstanceProfileName=profile_name, RoleName=role["RoleName"])
        iam.delete_instance_profile(InstanceProfileName=profile_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _delete_role(iam, role_name):
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
