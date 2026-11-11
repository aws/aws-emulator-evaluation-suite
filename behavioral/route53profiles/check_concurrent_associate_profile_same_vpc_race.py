"""concurrent-associate-profile-same-vpc-race."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-associate-profile-same-vpc-race"
GROUP = "concurrency"
SERVICES = ["route53profiles"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Racing AssociateProfile for two Profiles against the same VPC: at most one ends up COMPLETE."""
    r53p = ctx.client("route53profiles")

    vpc_id = _create_vpc(ctx)
    profile_a = _create_profile(ctx)
    profile_b = _create_profile(ctx)
    ctx.on_cleanup(
        lambda: _swallow_not_found(
            lambda: r53p.disassociate_profile(ProfileId=profile_a, ResourceId=vpc_id)
        )
    )
    ctx.on_cleanup(
        lambda: _swallow_not_found(
            lambda: r53p.disassociate_profile(ProfileId=profile_b, ResourceId=vpc_id)
        )
    )

    def _race(profile_id: str):
        try:
            resp = r53p.associate_profile(
                ProfileId=profile_id, ResourceId=vpc_id, Name=ctx.unique_name("sim2real-behav-race-")
            )
            return ("ok", resp["ProfileAssociation"]["Id"])
        except ClientError as err:
            return ("error", err.response["Error"]["Code"])

    with ThreadPoolExecutor(max_workers=2) as pool:
        fut_a = pool.submit(_race, profile_a)
        fut_b = pool.submit(_race, profile_b)
        result_a = fut_a.result()
        result_b = fut_b.result()

    def _complete_count() -> int:
        listing = r53p.list_profile_associations(ResourceId=vpc_id)["ProfileAssociations"]
        # give any still-in-flight association a chance to leave CREATING
        if any(a["Status"] == "CREATING" for a in listing):
            return -1
        return sum(1 for a in listing if a["Status"] == "COMPLETE")

    complete_count = _poll_until(
        probe=_complete_count,
        predicate=lambda n: n >= 0,
        timeout_s=120,
        interval_s=3,
    )

    assert complete_count == 1, (
        f"expected exactly one COMPLETE association for the VPC, got {complete_count} "
        f"(sync results: a={result_a}, b={result_b})"
    )


def _swallow_not_found(fn) -> None:
    try:
        fn()
    except ClientError as err:
        if err.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


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
        CidrBlock="10.82.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": name}]}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    return vpc_id


def _create_profile(ctx) -> str:
    r53p = ctx.client("route53profiles")
    name = ctx.unique_name("sim2real-behav-profile-")
    profile_id = r53p.create_profile(Name=name, ClientToken=ctx.unique_name("sim2real-behav-token-"))[
        "Profile"
    ]["Id"]
    ctx.on_cleanup(lambda: _swallow_not_found(lambda: r53p.delete_profile(ProfileId=profile_id)))
    return profile_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
