"""untag-resource-removes-tag."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "untag-resource-removes-tag"
GROUP = "state"
SERVICES = ["route53profiles"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UntagResource removes only the requested key, leaving other tags on the resource intact."""
    r53p = ctx.client("route53profiles")
    profile_id, profile_arn = _create_profile(ctx)

    r53p.tag_resource(
        ResourceArn=profile_arn,
        Tags={"sim2real-keep": "yes", "sim2real-drop": "yes"},
    )
    r53p.untag_resource(ResourceArn=profile_arn, TagKeys=["sim2real-drop"])

    tags = r53p.list_tags_for_resource(ResourceArn=profile_arn)["Tags"]
    assert tags == {"sim2real-keep": "yes"}, f"expected only sim2real-keep to survive untag, got {tags}"


def _create_profile(ctx):
    r53p = ctx.client("route53profiles")
    name = ctx.unique_name("sim2real-behav-profile-")
    deadline = time.monotonic() + min(400, ctx.time_left() or 400)
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
