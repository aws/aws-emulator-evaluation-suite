"""delete-profile-with-active-association-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-profile-with-active-association-rejected"
GROUP = "overly-permissive"
SERVICES = ["route53profiles"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteProfile on a Profile with a live VPC association is rejected with ConflictException."""
    r53p = ctx.client("route53profiles")

    vpc_id = _create_vpc(ctx)
    profile_id = _create_profile(ctx)

    assoc_id = r53p.associate_profile(
        ProfileId=profile_id, ResourceId=vpc_id, Name=ctx.unique_name("sim2real-behav-assoc-")
    )["ProfileAssociation"]["Id"]
    ctx.on_cleanup(
        lambda: _swallow_not_found(
            lambda: r53p.disassociate_profile(ProfileId=profile_id, ResourceId=vpc_id)
        )
    )

    _poll_until(
        probe=lambda: r53p.list_profile_associations(ProfileId=profile_id)["ProfileAssociations"][0][
            "Status"
        ],
        predicate=lambda s: s in ("COMPLETE", "FAILED"),
        timeout_s=420,
        interval_s=5,
    )

    error = _client_error(lambda: r53p.delete_profile(ProfileId=profile_id))
    assert error["Code"] == "ConflictException", f"expected ConflictException, got {error['Code']!r}"
    expected_message = (
        f'[RSLVR-05102] The Profile is associated with a resource: "{assoc_id}". '
        "Delete the association and try again."
    )
    assert error["Message"] == expected_message, f"expected {expected_message!r}, got {error['Message']!r}"

    # the profile must still exist -- deletion did not partially apply
    still_there = r53p.get_profile(ProfileId=profile_id)["Profile"]
    assert still_there["Id"] == profile_id, f"expected profile {profile_id!r} to still exist, got {still_there['Id']!r}"
    assert still_there["Status"] != "DELETED", f"expected profile not marked DELETED after rejected delete, got status {still_there['Status']!r}"

    # positive control: after disassociating, delete succeeds
    r53p.disassociate_profile(ProfileId=profile_id, ResourceId=vpc_id)
    _poll_until(
        probe=lambda: len(r53p.list_profile_associations(ProfileId=profile_id)["ProfileAssociations"]),
        predicate=lambda n: n == 0,
        timeout_s=180,
        interval_s=3,
    )
    r53p.delete_profile(ProfileId=profile_id)
    _poll_until(
        probe=lambda: _is_gone(lambda: r53p.get_profile(ProfileId=profile_id)),
        predicate=bool,
        timeout_s=90,
        interval_s=3,
    )
    gone = _client_error(lambda: r53p.get_profile(ProfileId=profile_id))
    assert gone["Code"] == "ResourceNotFoundException", f"expected ResourceNotFoundException after delete, got {gone['Code']!r}"
    gone_message = f'[RSLVR-05007] Can\'t find the resource with ID "{profile_id}".'
    assert gone["Message"] == gone_message, f"expected {gone_message!r}, got {gone['Message']!r}"


def _client_error(fn):
    """Call fn(); return its error (Code and Message). An unexpected SUCCESS raises: a target
    that accepts what real AWS refuses must fail loudly, not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _is_gone(fn) -> bool:
    """Poll probe: True once fn() fails not-found, False while it still succeeds."""
    try:
        fn()
    except ClientError as err:
        if err.response["Error"]["Code"] == "ResourceNotFoundException":
            return True
        raise
    return False


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last value={last!r}")


def _create_vpc(ctx) -> str:
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-behav-vpc-")
    vpc_id = ec2.create_vpc(
        CidrBlock="10.81.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": name}]}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    return vpc_id


def _create_profile(ctx) -> str:
    r53p = ctx.client("route53profiles")
    name = ctx.unique_name("sim2real-behav-profile-")
    deadline = time.monotonic() + min(400, ctx.time_left() or 400)
    while True:
        try:
            profile_id = r53p.create_profile(
                Name=name, ClientToken=ctx.unique_name("sim2real-behav-token-")
            )["Profile"]["Id"]
            break
        except ClientError as err:
            if err.response["Error"]["Code"] != "LimitExceededException" or time.monotonic() > deadline:
                raise
            time.sleep(2)
    ctx.on_cleanup(lambda: _delete_profile_blocking(r53p, profile_id))
    return profile_id


def _delete_profile_blocking(r53p, profile_id: str) -> None:
    try:
        r53p.delete_profile(ProfileId=profile_id)
    except ClientError as err:
        if err.response["Error"]["Code"] == "ResourceNotFoundException":
            return
        raise
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        try:
            r53p.get_profile(ProfileId=profile_id)
        except ClientError as err:
            if err.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(3)


def _swallow_not_found(fn) -> None:
    try:
        fn()
    except ClientError as err:
        if err.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
