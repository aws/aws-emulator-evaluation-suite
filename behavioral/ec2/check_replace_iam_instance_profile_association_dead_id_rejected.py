"""replace-iam-instance-profile-association-dead-id-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "replace-iam-instance-profile-association-dead-id-rejected"
GROUP = "error-semantics"
SERVICES = ["ec2", "iam"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ReplaceIamInstanceProfileAssociation rejects the association id a prior replace already
    retired, and the identical call against the current association id succeeds."""
    ec2 = ctx.client("ec2")
    iam = ctx.client("iam")

    trust_policy = json.dumps({
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    })
    profile_a_name, _ = _make_role_and_profile(ctx, iam, "a", trust_policy)
    profile_b_name, _ = _make_role_and_profile(ctx, iam, "b", trust_policy)

    ami_id = _latest_al2023_ami(ec2)
    instance_id = _run_instance_with_retry(ec2, ami_id, profile_a_name, ctx)
    ctx.on_cleanup(lambda: _terminate_instance(ec2, instance_id))
    ec2.get_waiter("instance_running").wait(InstanceIds=[instance_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    first_assoc = _poll_until(
        lambda: _find_association(ec2, instance_id),
        lambda a: a is not None,
        timeout_s=60,
        interval_s=3,
    )
    first_assoc_id = first_assoc["AssociationId"]

    second = ec2.replace_iam_instance_profile_association(
        AssociationId=first_assoc_id, IamInstanceProfile={"Name": profile_b_name}
    )["IamInstanceProfileAssociation"]
    second_assoc_id = second["AssociationId"]
    assert second_assoc_id != first_assoc_id, (
        f"expected a fresh association id, got the same id {first_assoc_id!r} reused"
    )
    _poll_until(
        lambda: ec2.describe_iam_instance_profile_associations(AssociationIds=[second_assoc_id])[
            "IamInstanceProfileAssociations"
        ][0]["State"],
        lambda state: state == "associated",
        timeout_s=60,
        interval_s=3,
    )

    # error boundary: the first association id is now retired by the replace above, and
    # using it again is rejected -- not silently treated as the still-current association.
    code, message = _error(
        lambda: ec2.replace_iam_instance_profile_association(
            AssociationId=first_assoc_id, IamInstanceProfile={"Name": profile_a_name}
        )
    )
    assert code == "InvalidAssociationID.NotFound", (
        f"expected InvalidAssociationID.NotFound, got {code}: {message}"
    )
    expected_message = f"An invalid association-id of '{first_assoc_id}' was given"
    assert message == expected_message, f"unexpected message: {message!r}"

    # effect absent: the rejected call must not have moved the instance off profile b.
    unchanged = ec2.describe_iam_instance_profile_associations(AssociationIds=[second_assoc_id])[
        "IamInstanceProfileAssociations"
    ][0]
    assert unchanged["IamInstanceProfile"]["Arn"].endswith(f"/{profile_b_name}"), (
        f"a rejected replace on the dead id must leave the instance on {profile_b_name!r}, "
        f"got {unchanged['IamInstanceProfile']['Arn']!r}"
    )

    # positive control: the identical shape of call succeeds against the CURRENT association id.
    third = ec2.replace_iam_instance_profile_association(
        AssociationId=second_assoc_id, IamInstanceProfile={"Name": profile_a_name}
    )["IamInstanceProfileAssociation"]
    assert third["IamInstanceProfile"]["Arn"].endswith(f"/{profile_a_name}"), (
        f"expected profile {profile_a_name!r} after replacing the current association, "
        f"got {third['IamInstanceProfile']['Arn']!r}"
    )


def _make_role_and_profile(ctx, iam, suffix, trust_policy):
    role_name = ctx.unique_name(f"sim2real-iprole-{suffix}-")
    profile_name = ctx.unique_name(f"sim2real-ipprof-{suffix}-")
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=trust_policy)
    ctx.on_cleanup(lambda: _delete_role(iam, role_name))
    iam.create_instance_profile(InstanceProfileName=profile_name)
    ctx.on_cleanup(lambda: _delete_profile(iam, profile_name))
    iam.add_role_to_instance_profile(InstanceProfileName=profile_name, RoleName=role_name)
    return profile_name, role_name


def _delete_role(iam, role_name):
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _delete_profile(iam, profile_name):
    try:
        roles = iam.get_instance_profile(InstanceProfileName=profile_name)["InstanceProfile"]["Roles"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "NoSuchEntity":
            return
        raise
    for role in roles:
        iam.remove_role_from_instance_profile(
            InstanceProfileName=profile_name, RoleName=role["RoleName"]
        )
    try:
        iam.delete_instance_profile(InstanceProfileName=profile_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


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
            if exc.response["Error"]["Code"] != "InvalidParameterValue":
                raise
            time.sleep(5)
    raise AssertionError(f"instance profile never became usable: {last_exc}")


def _terminate_instance(ec2, instance_id):
    try:
        ec2.terminate_instances(InstanceIds=[instance_id])
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "InvalidInstanceID.NotFound":
            return
        raise
    ec2.get_waiter("instance_terminated").wait(InstanceIds=[instance_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})


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
    if not images:
        raise AssertionError("no Amazon Linux 2023 AMI found in this region")
    images.sort(key=lambda i: i["CreationDate"], reverse=True)
    return images[0]["ImageId"]


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. A SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
