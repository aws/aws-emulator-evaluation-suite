"""instance-profile-path-preserved-through-launch."""
from __future__ import annotations

import json
import sys
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "instance-profile-path-preserved-through-launch"
GROUP = "iam-ec2-boundary"
SERVICES = ["ec2", "iam"]

_TYPE = "t3.micro"
_PATH = "/sim2real-profile-path-test/"
_AL2023_AMI_PARAM = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
_GONE_CODES = ("InvalidInstanceID.NotFound", "NoSuchEntity")


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An instance profile with a non-default Path, launched by name, is reported by both
    DescribeInstances and DescribeIamInstanceProfileAssociations with IAM's full Arn, path included.
    """
    ec2 = ctx.client("ec2")
    iam = ctx.client("iam")
    st: dict = {"instances": []}
    try:
        _build(ctx, ec2, iam, st)
        _legs(ctx, ec2, iam, st)
    finally:
        _teardown(ec2, iam, st)


def _legs(ctx, ec2, iam, st) -> None:
    expected_arn = f"arn:aws:iam::{ctx.account}:instance-profile{_PATH}{st['profile_name']}"
    assert st["profile_arn"] == expected_arn, (
        f"sanity: CreateInstanceProfile's own Arn should already be {expected_arn!r}, "
        f"got {st['profile_arn']!r}"
    )

    launched = _call_with_retry(lambda: ec2.run_instances(
        ImageId=st["ami"], InstanceType=_TYPE, MinCount=1, MaxCount=1,
        IamInstanceProfile={"Name": st["profile_name"]},
        TagSpecifications=[{"ResourceType": "instance", "Tags": _tags_for(st["name"])}],
        SubnetId=ctx.network().subnet_ids[0],
    ))
    instance_id = launched["Instances"][0]["InstanceId"]
    st["instances"].append(instance_id)

    described = _poll(
        lambda: _describe(ec2, instance_id),
        lambda i: i is not None and i.get("IamInstanceProfile"),
        timeout_s=180.0, interval_s=5.0,
        what=f"instance {instance_id} reporting an IamInstanceProfile",
    )
    described_arn = described["IamInstanceProfile"]["Arn"]
    assert described_arn == expected_arn, (
        f"DescribeInstances must report the instance profile's full-path Arn {expected_arn!r}, "
        f"got {described_arn!r}"
    )

    assoc = _poll(
        lambda: _association_for(ec2, instance_id),
        lambda a: a is not None,
        timeout_s=60.0, interval_s=5.0,
        what=f"DescribeIamInstanceProfileAssociations reporting an association for {instance_id}",
    )
    assoc_arn = assoc["IamInstanceProfile"]["Arn"]
    assert assoc_arn == expected_arn, (
        f"DescribeIamInstanceProfileAssociations must independently agree on the full-path Arn "
        f"{expected_arn!r}, got {assoc_arn!r}"
    )
    assert assoc_arn == described_arn, (
        f"DescribeInstances and DescribeIamInstanceProfileAssociations disagree on the Arn for "
        f"the same instance's instance profile: {described_arn!r} vs {assoc_arn!r}"
    )


def _build(ctx, ec2, iam, st) -> None:
    name = ctx.unique_name("sim2real-xsvc-ippath-")
    st["name"] = name

    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_name = name + "-role"
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": "1"}],
    )
    st["role_name"] = role_name
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    profile_name = name + "-profile"
    profile = iam.create_instance_profile(
        InstanceProfileName=profile_name, Path=_PATH,
        Tags=[{"Key": "sim2real", "Value": "1"}],
    )["InstanceProfile"]
    st["profile_name"] = profile_name
    st["profile_arn"] = profile["Arn"]
    ctx.on_cleanup(lambda: iam.delete_instance_profile(InstanceProfileName=profile_name))

    iam.add_role_to_instance_profile(InstanceProfileName=profile_name, RoleName=role_name)
    ctx.on_cleanup(lambda: iam.remove_role_from_instance_profile(
        InstanceProfileName=profile_name, RoleName=role_name))

    ami = ctx.client("ssm").get_parameter(Name=_AL2023_AMI_PARAM)["Parameter"]["Value"]
    assert ami.startswith("ami-"), f"{_AL2023_AMI_PARAM} must resolve to an AMI id, got {ami!r}"
    st["ami"] = ami


def _teardown(ec2, iam, st) -> None:
    left: list[str] = []

    steps: list = []

    def _step(label, fn):
        steps.append((label, fn))

    for iid in st.get("instances", []):
        _step(f"instance {iid}", lambda i=iid: ec2.terminate_instances(InstanceIds=[i]))
    for iid in st.get("instances", []):
        _step(f"instance-wait {iid}", lambda i=iid: _poll(
            lambda: _state(ec2, i), lambda s: s in ("terminated", "__gone__"),
            timeout_s=600.0, interval_s=5.0, what=f"instance {i} reaching 'terminated'"))
    for label, fn in steps:
        try:
            fn()
        except ClientError as exc:
            if _code(exc) not in _GONE_CODES:
                left.append(f"{label}: {_code(exc)}")
        except Exception as exc:  # noqa: BLE001 - collected, raised below
            left.append(f"{label}: {exc!r}")
    if left:
        found = sys.exc_info()[1]
        raise AssertionError(
            (f"{found!r}; " if found else "")
            + f"teardown could not remove everything the check created: {left!r}"
        )


def _tags_for(name):
    return [{"Key": "sim2real", "Value": "1"}, {"Key": "Name", "Value": name}]


def _code(exc):
    return exc.response.get("Error", {}).get("Code")


def _call_with_retry(fn, codes=("InvalidParameterValue",), retries=20, delay=5.0):
    """RunInstances with a just-created IamInstanceProfile needs IAM's association to have
    propagated; retry on the specific not-yet-usable error rather than sleeping blindly."""
    last = None
    for _ in range(retries):
        try:
            return fn()
        except ClientError as exc:
            last = exc
            if _code(exc) in codes:
                time.sleep(delay)
                continue
            raise
    raise last


def _poll(probe, predicate, *, timeout_s, interval_s, what):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{what} was not observed within {timeout_s}s; last saw {last!r}")


def _describe(ec2, instance_id):
    try:
        resv = ec2.describe_instances(InstanceIds=[instance_id])["Reservations"]
    except ClientError as exc:
        if _code(exc) == "InvalidInstanceID.NotFound":
            return None
        raise
    if not resv or not resv[0].get("Instances"):
        return None
    return resv[0]["Instances"][0]


def _state(ec2, instance_id):
    inst = _describe(ec2, instance_id)
    return "__gone__" if inst is None else inst["State"]["Name"]


def _association_for(ec2, instance_id):
    assocs = ec2.describe_iam_instance_profile_associations(
        Filters=[{"Name": "instance-id", "Values": [instance_id]}]
    )["IamInstanceProfileAssociations"]
    live = [a for a in assocs if a["State"] in ("associating", "associated")]
    return live[0] if live else None


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
