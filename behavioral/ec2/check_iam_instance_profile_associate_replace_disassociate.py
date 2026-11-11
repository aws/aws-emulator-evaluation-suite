"""iam-instance-profile-associate-replace-disassociate."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "iam-instance-profile-associate-replace-disassociate"
GROUP = 'instance-lifecycle'
SERVICES = ['ec2']

ERR_ASSOC_NOT_FOUND = 'InvalidAssociationID.NotFound'
_TRUST = json.dumps(
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

# ===== helpers (self-contained) =====


def _code(exc):
    return exc.response.get("Error", {}).get("Code")


def _test_ami_id(ec2):
    """Return an x86_64 HVM EBS ImageId usable for RunInstances tests."""
    strict = [
        {"Name": "state", "Values": ["available"]},
        {"Name": "architecture", "Values": ["x86_64"]},
        {"Name": "virtualization-type", "Values": ["hvm"]},
        {"Name": "root-device-type", "Values": ["ebs"]},
    ]
    attempts = [
        {"Owners": ["amazon"], "Filters": strict + [{"Name": "name", "Values": ["al2023-ami-2023*-x86_64"]}]},
        {"Owners": ["amazon"], "Filters": strict + [{"Name": "name", "Values": ["amzn2-ami-hvm-*-x86_64-gp2"]}]},
        {"Owners": ["amazon"], "Filters": strict},
    ]
    for kw in attempts:
        try:
            images = ec2.describe_images(**kw).get("Images", [])
        except ClientError:
            continue
        if not images:
            continue
        images.sort(key=lambda i: i.get("CreationDate", ""), reverse=True)
        return images[0]["ImageId"]
    raise AssertionError("could not discover a usable test AMI")


def _get_default_subnet(ec2, *, ctx):
    try:
        subnets = ec2.describe_subnets(
            Filters=[{"Name": "subnet-id", "Values": ctx.network().subnet_ids}]
        ).get("Subnets", [])
    except ClientError as exc:
        raise AssertionError(f"could not list network subnets: {exc}")
    if not subnets:
        raise AssertionError("account has no network subnet for AZ-pinned launches")
    return subnets[0]["SubnetId"]


def _wait_instance_state(ec2, instance_id, state, timeout_s=240):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            resv = ec2.describe_instances(InstanceIds=[instance_id]).get("Reservations", [])
        except ClientError as exc:
            if _code(exc) == "InvalidInstanceID.NotFound":
                last = "__not_yet_visible__"
                time.sleep(3)
                continue
            raise
        last = resv[0]["Instances"][0]["State"]["Name"] if resv and resv[0].get("Instances") else "__none__"
        if last == state:
            return last
        time.sleep(3)
    raise AssertionError(f"instance {instance_id} never reached {state!r} in {timeout_s}s (last {last!r})")


def _associate_with_iam_propagation(ec2, profile_name, instance_id, timeout_s=180):
    """AssociateIamInstanceProfile races IAM propagation of a just-created profile: EC2 answers
    InvalidParameterValue until the profile is visible to it. Retry to a bounded deadline."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            return ec2.associate_iam_instance_profile(
                IamInstanceProfile={"Name": profile_name}, InstanceId=instance_id
            )["IamInstanceProfileAssociation"]
        except ClientError as exc:
            last = _code(exc)
            if last not in ("InvalidParameterValue", "RequestLimitExceeded"):
                raise
            time.sleep(5)
    raise AssertionError(
        f"AssociateIamInstanceProfile({profile_name}) never succeeded in {timeout_s}s (last error {last!r})"
    )


def _wait_assoc_state(ec2, association_id, state, timeout_s=180):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        assocs = ec2.describe_iam_instance_profile_associations(
            AssociationIds=[association_id]
        ).get("IamInstanceProfileAssociations", [])
        last = assocs[0]["State"] if assocs else "__none__"
        if last == state:
            return assocs[0]
        time.sleep(3)
    raise AssertionError(
        f"association {association_id} never reached {state!r} in {timeout_s}s (last {last!r})"
    )


def _assocs_for_instance(ec2, instance_id):
    return [
        a
        for a in ec2.describe_iam_instance_profile_associations(
            Filters=[{"Name": "instance-id", "Values": [instance_id]}]
        ).get("IamInstanceProfileAssociations", [])
        if a["State"] != "disassociated"
    ]


def _drop_profile(iam, profile_name, role_name):
    try:
        iam.remove_role_from_instance_profile(InstanceProfileName=profile_name, RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_instance_profile(InstanceProfileName=profile_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


# ===== end helpers =====


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AssociateIamInstanceProfile -> Replace -> Disassociate is a real association resource with its
    own id and associating -> associated state, not a mutable field on the instance: every "give this
    instance a role" workflow depends on it."""
    ec2 = ctx.client("ec2")
    iam = ctx.client("iam")
    base = ctx.unique_name("sim2real-behav-")
    role_a, role_b = f"{base}-a", f"{base}-b"
    prof_a, prof_b = f"{base}-a", f"{base}-b"

    for role, prof in ((role_a, prof_a), (role_b, prof_b)):
        iam.create_role(RoleName=role, AssumeRolePolicyDocument=_TRUST)
        ctx.on_cleanup(lambda r=role: iam.delete_role(RoleName=r))
        iam.create_instance_profile(InstanceProfileName=prof)
        ctx.on_cleanup(lambda p=prof, r=role: _drop_profile(iam, p, r))
        iam.add_role_to_instance_profile(InstanceProfileName=prof, RoleName=role)
    arn_a = iam.get_instance_profile(InstanceProfileName=prof_a)["InstanceProfile"]["Arn"]
    arn_b = iam.get_instance_profile(InstanceProfileName=prof_b)["InstanceProfile"]["Arn"]

    subnet_id = _get_default_subnet(ec2, ctx=ctx)
    instance_id = ec2.run_instances(
        ImageId=_test_ami_id(ec2), InstanceType="t3.micro", MinCount=1, MaxCount=1,
        SubnetId=subnet_id,
        TagSpecifications=[{"ResourceType": "instance", "Tags": [{"Key": "sim2real", "Value": "1"}]}],
    )["Instances"][0]["InstanceId"]
    ctx.on_cleanup(lambda: ec2.terminate_instances(InstanceIds=[instance_id]))
    _wait_instance_state(ec2, instance_id, "running")

    # --- associate: a NEW association resource with its own id + state machine ---
    assoc1 = _associate_with_iam_propagation(ec2, prof_a, instance_id)
    id1 = assoc1["AssociationId"]
    ctx.on_cleanup(lambda: _unless_gone(lambda: ec2.disassociate_iam_instance_profile(AssociationId=id1), "InvalidAssociationID.NotFound"))
    assert id1.startswith("iip-assoc-"), f"expected an iip-assoc- association id, got {id1!r}"
    assert assoc1["State"] in ("associating", "associated"), (
        f"expected associating|associated on create, got {assoc1['State']!r}"
    )
    settled = _wait_assoc_state(ec2, id1, "associated")
    assert settled["InstanceId"] == instance_id, f"association points at {settled['InstanceId']!r}"
    assert settled["IamInstanceProfile"]["Arn"] == arn_a, (
        f"expected profile {arn_a}, got {settled['IamInstanceProfile']['Arn']}"
    )

    # --- replace: a DIFFERENT association id now points at the second profile ---
    assoc2 = ec2.replace_iam_instance_profile_association(
        IamInstanceProfile={"Name": prof_b}, AssociationId=id1
    )["IamInstanceProfileAssociation"]
    id2 = assoc2["AssociationId"]
    ctx.on_cleanup(lambda: _unless_gone(lambda: ec2.disassociate_iam_instance_profile(AssociationId=id2), "InvalidAssociationID.NotFound"))
    assert id2 != id1, f"Replace must mint a new association id, reused {id1}"
    replaced = _wait_assoc_state(ec2, id2, "associated")
    assert replaced["IamInstanceProfile"]["Arn"] == arn_b, (
        f"expected profile {arn_b} after replace, got {replaced['IamInstanceProfile']['Arn']}"
    )
    live = _assocs_for_instance(ec2, instance_id)
    assert [a["AssociationId"] for a in live] == [id2], (
        f"instance must hold exactly one live association ({id2}), got {[a['AssociationId'] for a in live]}"
    )

    # --- disassociate, then the SAME id is gone (not a silent second success) ---
    ec2.disassociate_iam_instance_profile(AssociationId=id2)
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline and _assocs_for_instance(ec2, instance_id):
        time.sleep(3)
    remaining = _assocs_for_instance(ec2, instance_id)
    assert remaining == [], f"expected no live association after disassociate, got {remaining}"

    try:
        ec2.disassociate_iam_instance_profile(AssociationId=id2)
    except ClientError as exc:
        assert _code(exc) == ERR_ASSOC_NOT_FOUND, (
            f"expected {ERR_ASSOC_NOT_FOUND} re-disassociating {id2}, got {_code(exc)}"
        )
        assert exc.response["Error"]["Message"] == (
            f"An invalid association-id of '{id2}' was given"), exc.response["Error"]
    else:
        raise AssertionError(
            f"re-disassociating {id2} must fail with {ERR_ASSOC_NOT_FOUND}, it succeeded"
        )
    assert _assocs_for_instance(ec2, instance_id) == [], "rejected re-disassociate must not change state"

    # --- control: the instance is still associable after the rejection ---
    assoc3 = _associate_with_iam_propagation(ec2, prof_a, instance_id)
    id3 = assoc3["AssociationId"]
    ctx.on_cleanup(lambda: _unless_gone(lambda: ec2.disassociate_iam_instance_profile(AssociationId=id3), "InvalidAssociationID.NotFound"))
    assert id3 not in (id1, id2), f"re-association must mint a fresh id, got {id3}"
    _wait_assoc_state(ec2, id3, "associated")


def _unless_gone(fn, *codes, message=None):
    """Run a teardown delete; a resource the check already removed is not a failure."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        if err.get("Code") not in codes or (message is not None and message not in err.get("Message", "")):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
