"""instance-profile-carries-its-role-arn-path-and-trust-until-removed."""

from __future__ import annotations

import json
import time
from urllib.parse import unquote

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "instance-profile-carries-its-role-arn-path-and-trust-until-removed"
GROUP = "e2e_workflows"
SERVICES = ["iam"]

#: IAM is eventually consistent: each read after a write converges within this bound and returns
#: as soon as the expected value or refusal holds.
_CONVERGE_S = 40

_EC2_TRUST = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"Service": "ec2.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }
    ],
}


@tags(
    "axis:happy-path",
    "cap:c1",
    "concern:negative-classes",
    "concern:representation",
    "plane:control",
)
def run(ctx) -> None:
    """An EC2 service role wired through an instance profile: the profile reports its own ARN and
    path and embeds the role's ARN, path and trust document; a second role is refused (one role
    per profile); removing the role empties both directions, and the deleted profile is gone."""
    iam = ctx.client("iam")
    partition = _partition(ctx)
    role_path = f"/ec2/{ctx.unique_name('rp-')}/"
    role_name = ctx.unique_name("sim2real-behav-ec2-role-")
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(_EC2_TRUST),
        Path=role_path,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda n=role_name: _quiet(lambda: iam.delete_role(RoleName=n)))
    other_role = ctx.unique_name("sim2real-behav-ec2-role2-")
    iam.create_role(
        RoleName=other_role,
        AssumeRolePolicyDocument=json.dumps(_EC2_TRUST),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda n=other_role: _quiet(lambda: iam.delete_role(RoleName=n)))
    role_arn = f"arn:{partition}:iam::{ctx.account}:role{role_path}{role_name}"

    profile_path = f"/profiles/{ctx.unique_name('ip-')}/"
    profile = ctx.unique_name("sim2real-behav-profile-")
    created = iam.create_instance_profile(
        InstanceProfileName=profile,
        Path=profile_path,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["InstanceProfile"]
    ctx.on_cleanup(
        lambda p=profile: _quiet(lambda: iam.delete_instance_profile(InstanceProfileName=p))
    )
    profile_arn = f"arn:{partition}:iam::{ctx.account}:instance-profile{profile_path}{profile}"
    assert created["Arn"] == profile_arn, (
        f"CreateInstanceProfile Arn {created['Arn']!r} != {profile_arn!r}"
    )
    assert created["Path"] == profile_path, (
        f"CreateInstanceProfile Path {created['Path']!r} != {profile_path!r}"
    )
    assert created["Roles"] == [], f"a new instance profile lists roles {created['Roles']!r}"

    iam.add_role_to_instance_profile(InstanceProfileName=profile, RoleName=role_name)
    ctx.on_cleanup(
        lambda p=profile, r=role_name: _quiet(
            lambda: iam.remove_role_from_instance_profile(InstanceProfileName=p, RoleName=r)
        )
    )
    roles = _converge(
        lambda: iam.get_instance_profile(InstanceProfileName=profile)["InstanceProfile"]["Roles"],
        lambda rs: len(rs) == 1,
    )
    assert [(r["RoleName"], r["Arn"], r["Path"]) for r in roles] == [
        (role_name, role_arn, role_path)
    ], (
        f"GetInstanceProfile Roles {[(r.get('RoleName'), r.get('Arn'), r.get('Path')) for r in roles]!r}, "
        f"expected exactly the one role with its ARN and path"
    )
    trust = _policy_doc(roles[0]["AssumeRolePolicyDocument"])
    assert trust == _policy_doc(_EC2_TRUST), (
        f"the embedded role's trust document {trust!r} != the document sent"
    )
    for_role = _converge(
        lambda: _profiles_for(iam, role_name), lambda got: got == [(profile, profile_arn)]
    )
    assert for_role == [(profile, profile_arn)], (
        f"ListInstanceProfilesForRole {for_role!r}, expected exactly {[(profile, profile_arn)]!r}"
    )

    # One role per instance profile is a fixed limit: a second role is refused and not added.
    got = _refusal(
        _error(
            lambda: iam.add_role_to_instance_profile(
                InstanceProfileName=profile, RoleName=other_role
            )
        ),
        409,
    )
    limit = ("LimitExceeded", "Cannot exceed quota for InstanceSessionsPerInstanceProfile: 1")
    assert got == limit, (
        f"AddRoleToInstanceProfile with a second role: expected {limit}, got {got!r}"
    )
    names = [
        r["RoleName"]
        for r in iam.get_instance_profile(InstanceProfileName=profile)["InstanceProfile"]["Roles"]
    ]
    assert names == [role_name], (
        f"after the refused add the profile lists {names!r}, expected only the first role"
    )
    assert _profiles_for(iam, other_role) == [], "the refused role reports an instance profile"

    iam.remove_role_from_instance_profile(InstanceProfileName=profile, RoleName=role_name)
    roles = _converge(
        lambda: iam.get_instance_profile(InstanceProfileName=profile)["InstanceProfile"]["Roles"],
        lambda rs: rs == [],
    )
    assert roles == [], (
        f"after RemoveRoleFromInstanceProfile the profile lists {len(roles)} role(s)"
    )
    for_role = _converge(lambda: _profiles_for(iam, role_name), lambda got: got == [])
    assert for_role == [], f"after removal ListInstanceProfilesForRole {for_role!r}, expected none"

    iam.delete_instance_profile(InstanceProfileName=profile)
    gone = ("NoSuchEntity", f"Instance Profile {profile} cannot be found.")
    got = _refusal(
        _eventual_error(lambda: iam.get_instance_profile(InstanceProfileName=profile)), 404
    )
    assert got == gone, f"GetInstanceProfile on the deleted profile: expected {gone}, got {got!r}"
    got = _refusal(
        _eventual_error(
            lambda: iam.add_role_to_instance_profile(
                InstanceProfileName=profile, RoleName=role_name
            )
        ),
        404,
    )
    assert got == gone, (
        f"AddRoleToInstanceProfile on the deleted profile: expected {gone}, got {got!r}"
    )
    # The role outlives its profile.
    assert iam.get_role(RoleName=role_name)["Role"]["Arn"] == role_arn, (
        "the role did not survive its profile"
    )


def _profiles_for(iam, role_name):
    return sorted(
        (p["InstanceProfileName"], p["Arn"])
        for page in iam.get_paginator("list_instance_profiles_for_role").paginate(
            RoleName=role_name
        )
        for p in page["InstanceProfiles"]
    )


def _partition(ctx) -> str:
    """The caller's partition, taken from its own ARN — never a literal 'aws'."""
    arn = ctx.client("sts").get_caller_identity()["Arn"]
    parts = arn.split(":")
    assert len(parts) > 2 and parts[0] == "arn" and parts[1], (
        f"GetCallerIdentity returned Arn {arn!r}, from which no partition can be read"
    )
    return parts[1]


def _converge(probe, ok, timeout_s=_CONVERGE_S, interval_s=2.0):
    """Re-read until ok(value) holds or the bound passes; return the last value read."""
    deadline = time.monotonic() + timeout_s
    while True:
        value = probe()
        if ok(value) or time.monotonic() >= deadline:
            return value
        time.sleep(interval_s)


def _error(fn):
    """The error response of fn(); a call that succeeds raises AssertionError."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _eventual_error(fn, timeout_s=_CONVERGE_S, interval_s=2.0):
    """Like _error, but a call that still succeeds is retried until the bound passes (IAM's
    deletes propagate eventually); a success at the deadline raises AssertionError."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            result = fn()
        except ClientError as exc:
            return exc.response
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"expected the call to be rejected within {timeout_s}s, but it still succeeds: {result!r}"
            )
        time.sleep(interval_s)


def _refusal(resp, status):
    """(code, message) of a refusal, after grading its HTTP status class (AWS answers `status`)."""
    err = resp.get("Error", {})
    got_status = resp.get("ResponseMetadata", {}).get("HTTPStatusCode")
    assert isinstance(got_status, int) and got_status // 100 == status // 100, (
        f"expected HTTP {status // 100}xx for {err.get('Code')!r}, got {got_status!r}"
    )
    return err.get("Code"), err.get("Message")


def _policy_doc(doc):
    """A policy document as a comparable value: parsed from JSON (URL-decoded when IAM returns it
    encoded), with each single-element list read as its one element, as IAM treats them alike."""
    if isinstance(doc, str):
        doc = json.loads(unquote(doc) if doc.lstrip().startswith("%") else doc)
    return _collapse(doc)


def _collapse(value):
    if isinstance(value, list):
        items = [_collapse(v) for v in value]
        return items[0] if len(items) == 1 else items
    if isinstance(value, dict):
        return {k: _collapse(v) for k, v in value.items()}
    return value


def _quiet(fn):
    """Teardown call that tolerates the resource already being gone (the body deletes it)."""
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NoSuchEntity":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
