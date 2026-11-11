"""tag-resource-and-list-tags."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-resource-and-list-tags"
GROUP = "state"
SERVICES = ["route53profiles"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource attaches tags to a Profile ARN and ListTagsForResource reflects exactly those tags."""
    r53p = ctx.client("route53profiles")
    profile_id, profile_arn = _create_profile(ctx)

    want = {"sim2real-env": "test", "sim2real-owner": "behavioral"}
    r53p.tag_resource(ResourceArn=profile_arn, Tags=want)

    got = r53p.list_tags_for_resource(ResourceArn=profile_arn)["Tags"]
    assert got == want, f"ListTagsForResource expected {want}, got {got}"


def _create_profile(ctx):
    r53p = ctx.client("route53profiles")
    name = ctx.unique_name("sim2real-behav-profile-")
    # Deadline must leave headroom under the check's own DEFAULT_TIMEOUT_S (300s) so a
    # persistent LimitExceededException surfaces as this raise, not as an opaque
    # harness-level timeout with no error code attached.
    deadline = time.monotonic() + min(240, ctx.time_left() or 240)
    while True:
        try:
            profile = r53p.create_profile(
                Name=name, ClientToken=ctx.unique_name("sim2real-behav-token-")
            )["Profile"]
            break
        except ClientError as err:
            if err.response["Error"]["Code"] != "LimitExceededException" or time.monotonic() > deadline:
                raise
            time.sleep(2)
    profile_id = profile["Id"]
    ctx.on_cleanup(lambda: _delete_profile_blocking(r53p, profile_id))
    return profile_id, profile["Arn"]


def _delete_profile_blocking(r53p, profile_id: str) -> None:
    try:
        r53p.delete_profile(ProfileId=profile_id)
    except ClientError as err:
        if err.response["Error"]["Code"] == "ResourceNotFoundException":
            return
        raise
    # Deadline must stay under DEFAULT_CLEANUP_TIMEOUT_S (60s): the engine abandons
    # this callback on a daemon thread past that budget regardless of what we ask for.
    deadline = time.monotonic() + 45
    while time.monotonic() < deadline:
        try:
            r53p.get_profile(ProfileId=profile_id)
        except ClientError as err:
            if err.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(3)
    raise AssertionError(f"profile {profile_id} still present {deadline - time.monotonic():.0f}s past delete deadline")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
