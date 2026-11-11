"""disassociate-profile-removes-association."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "disassociate-profile-removes-association"
GROUP = "state"
SERVICES = ["route53profiles"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DisassociateProfile tears the VPC association down; it eventually disappears from Get/List."""
    r53p = ctx.client("route53profiles")

    vpc_id = _create_vpc(ctx)
    profile_id = _create_profile(ctx)

    assoc = r53p.associate_profile(
        ProfileId=profile_id, ResourceId=vpc_id, Name=ctx.unique_name("sim2real-behav-assoc-")
    )["ProfileAssociation"]
    assoc_id = assoc["Id"]

    _poll_until(
        probe=lambda: r53p.get_profile_association(ProfileAssociationId=assoc_id)["ProfileAssociation"][
            "Status"
        ],
        predicate=lambda s: s in ("COMPLETE", "FAILED"),
        timeout_s=420,
        interval_s=5,
    )

    disassoc = r53p.disassociate_profile(ProfileId=profile_id, ResourceId=vpc_id)["ProfileAssociation"]
    assert disassoc["Id"] == assoc_id, f"expected disassociate response Id={assoc_id!r}, got {disassoc['Id']!r}"
    assert disassoc["Status"] in ("DELETING", "DELETED"), (
        f"expected disassociate response Status in ('DELETING', 'DELETED'), got {disassoc['Status']!r}"
    )

    _poll_until(
        probe=lambda: _is_gone(lambda: r53p.get_profile_association(ProfileAssociationId=assoc_id)),
        predicate=bool,
        timeout_s=180,
        interval_s=3,
    )
    gone = _client_error(lambda: r53p.get_profile_association(ProfileAssociationId=assoc_id))
    assert gone["Code"] == "ResourceNotFoundException", (
        f"expected GetProfileAssociation to settle into ResourceNotFoundException, got {gone['Code']!r}"
    )
    gone_message = f'[RSLVR-05007] Can\'t find the resource with ID "{assoc_id}".'
    assert gone["Message"] == gone_message, f"expected {gone_message!r}, got {gone['Message']!r}"

    remaining = r53p.list_profile_associations(ProfileId=profile_id)["ProfileAssociations"]
    remaining_ids = {a["Id"] for a in remaining}
    assert assoc_id not in remaining_ids, (
        f"expected {assoc_id!r} absent from ListProfileAssociations, still present in {remaining_ids!r}"
    )

    redisassoc = _client_error(lambda: r53p.disassociate_profile(ProfileId=profile_id, ResourceId=vpc_id))
    assert redisassoc["Code"] == "ResourceNotFoundException", (
        f"expected a second DisassociateProfile on the dead association to raise "
        f"ResourceNotFoundException, got {redisassoc['Code']!r}"
    )
    redisassoc_message = f'[RSLVR-05300] Can\'t locate the Profile ID: "{profile_id}" or resource ID "{vpc_id}".'
    assert redisassoc["Message"] == redisassoc_message, (
        f"expected {redisassoc_message!r}, got {redisassoc['Message']!r}"
    )


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
        CidrBlock="10.78.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": name}]}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    return vpc_id


def _create_profile(ctx) -> str:
    from botocore.exceptions import ClientError

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
    from botocore.exceptions import ClientError

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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
