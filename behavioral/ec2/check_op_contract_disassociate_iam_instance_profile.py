"""op-contract-disassociate-iam-instance-profile."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-disassociate-iam-instance-profile"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DisassociateIamInstanceProfile detaches a running instance's profile, whose association reaches
    disassociated; an unknown association ID fails with InvalidParameterValue and its exact message."""
    ec2 = ctx.client("ec2")
    iam = ctx.client("iam")

    role_name = ctx.unique_name("sim2real-iip-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy))
    ctx.on_cleanup(lambda: _safe(lambda: iam.delete_role(RoleName=role_name)))

    profile_name = ctx.unique_name("sim2real-iip-profile-")
    profile_arn = iam.create_instance_profile(InstanceProfileName=profile_name)["InstanceProfile"]["Arn"]
    ctx.on_cleanup(lambda: _safe(lambda: iam.delete_instance_profile(InstanceProfileName=profile_name)))
    iam.add_role_to_instance_profile(InstanceProfileName=profile_name, RoleName=role_name)
    ctx.on_cleanup(
        lambda: _safe(lambda: iam.remove_role_from_instance_profile(InstanceProfileName=profile_name, RoleName=role_name))
    )

    image_id = _latest_al2023_ami(ec2)
    instance_id = ec2.run_instances(
        ImageId=image_id,
        InstanceType="t3.micro",
        MinCount=1,
        MaxCount=1,
        TagSpecifications=[
            {"ResourceType": "instance", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-iip-inst-")}]}
        ],
        SubnetId=ctx.network().subnet_ids[0],
    )["Instances"][0]["InstanceId"]
    ctx.on_cleanup(lambda: _safe(lambda: ec2.terminate_instances(InstanceIds=[instance_id])))

    ec2.get_waiter("instance_running").wait(InstanceIds=[instance_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    association_id = _poll_until(
        lambda: _try_associate(ec2, instance_id, profile_arn),
        lambda v: v is not None,
        timeout_s=90.0,
        interval_s=5.0,
    )

    _poll_until(
        lambda: ec2.describe_iam_instance_profile_associations(AssociationIds=[association_id])[
            "IamInstanceProfileAssociations"
        ][0]["State"],
        lambda state: state == "associated",
        timeout_s=60.0,
        interval_s=3.0,
    )

    # Error boundary: the real association ID with every hex digit flipped (an all-zero suffix is
    # malformed). AWS rejects such an unrecognized association ID with InvalidParameterValue, not
    # InvalidAssociationID.NotFound.
    prefix, _, suffix = association_id.rpartition("-")
    bogus_association_id = f"{prefix}-" + "".join(format(int(c, 16) ^ 1, "x") for c in suffix)
    code, message = _client_error(
        lambda: ec2.disassociate_iam_instance_profile(AssociationId=bogus_association_id)
    )
    assert code == "InvalidParameterValue", f"expected InvalidParameterValue, got {code!r}"
    assert message == f"Invalid Id: {bogus_association_id}", (
        f"unexpected InvalidParameterValue message: {message!r}"
    )

    resp = ec2.disassociate_iam_instance_profile(AssociationId=association_id)
    assert resp["IamInstanceProfileAssociation"]["State"] in ("disassociating", "disassociated"), resp

    # Once disassociated, the association can drop out of DescribeIamInstanceProfileAssociations
    # (InvalidAssociationID.NotFound); that counts as the terminal state too.
    _poll_until(
        lambda: _assoc_state(ec2, association_id),
        lambda state: state in ("disassociated", None),
        timeout_s=60.0,
        interval_s=3.0,
    )


def _assoc_state(ec2, association_id):
    from botocore.exceptions import ClientError

    try:
        assocs = ec2.describe_iam_instance_profile_associations(AssociationIds=[association_id])[
            "IamInstanceProfileAssociations"
        ]
    except ClientError as e:
        if e.response["Error"]["Code"] == "InvalidAssociationID.NotFound":
            return None
        raise
    return assocs[0]["State"] if assocs else None


def _try_associate(ec2, instance_id, profile_arn):
    from botocore.exceptions import ClientError

    try:
        return ec2.associate_iam_instance_profile(
            IamInstanceProfile={"Arn": profile_arn}, InstanceId=instance_id
        )["IamInstanceProfileAssociation"]["AssociationId"]
    except ClientError as e:
        if e.response["Error"]["Code"] in ("InvalidParameterValue", "IncorrectState"):
            return None
        raise


def _latest_al2023_ami(ec2) -> str:
    images = ec2.describe_images(
        Owners=["amazon"],
        Filters=[
            {"Name": "name", "Values": ["al2023-ami-*-x86_64"]},
            {"Name": "state", "Values": ["available"]},
        ],
    )["Images"]
    images.sort(key=lambda img: img["CreationDate"], reverse=True)
    return images[0]["ImageId"]


def _client_error(fn):
    """Call fn(); return its error (code, message). An unexpected SUCCESS raises, because a
    target ACCEPTING a call real AWS refuses must not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, timeout_s=120.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last}")


def _safe(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("InvalidInstanceID.NotFound", "NoSuchEntity"):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
