"""associate-resource-unsupported-arn-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "associate-resource-unsupported-arn-rejected"
GROUP = "overly-permissive"
SERVICES = ["route53profiles"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AssociateResourceToProfile with a well-formed ARN of an unsupported resource type (an S3
    bucket) is refused with ValidationException ("[RSLVR-05022] The ARN in your request isn't valid
    ...") and no resource association with that ARN is listed.
    """
    r53p = ctx.client("route53profiles")

    profile_id = _create_profile(ctx)
    bogus_arn = f"arn:aws:s3:::{ctx.unique_name('sim2real-behav-bucket-')}"

    code, message = _error(
        lambda: r53p.associate_resource_to_profile(
            ProfileId=profile_id,
            ResourceArn=bogus_arn,
            Name=ctx.unique_name("sim2real-behav-resassoc-"),
        )
    )
    assert code == "ValidationException", (
        f"expected a validation-style rejection for an unsupported resource ARN, got {code!r}"
    )
    expected = f'[RSLVR-05022] The ARN in your request isn\'t valid:"{bogus_arn}". Provide a valid ARN.'
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # the invalid association must not have been created
    listing = r53p.list_profile_resource_associations(ProfileId=profile_id)["ProfileResourceAssociations"]
    assert not any(a["ResourceArn"] == bogus_arn for a in listing), (
        f"rejected association for {bogus_arn!r} should not appear in the profile's associations, "
        f"got {listing!r}"
    )


def _error(fn):
    """Call fn(); return its botocore error (code, message). A success raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"]["Message"]
    raise AssertionError(f"expected a rejection, but the call succeeded and returned {result!r}")


def _create_profile(ctx) -> str:
    r53p = ctx.client("route53profiles")
    name = ctx.unique_name("sim2real-behav-profile-")
    # Bounded well under the check's own 300s body timeout so a persistent
    # LimitExceededException surfaces as a clear raise instead of the harness
    # silently killing the check first.
    deadline = time.monotonic() + min(90, ctx.time_left() or 90)
    while True:
        try:
            profile_id = r53p.create_profile(
                Name=name,
                ClientToken=ctx.unique_name("sim2real-behav-token-"),
                Tags=[{"Key": "sim2real-behav", "Value": "associate-resource-unsupported-arn-rejected"}],
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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
