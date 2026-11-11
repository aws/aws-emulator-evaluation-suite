"""get-profile-nonexistent-not-found."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-profile-nonexistent-not-found"
GROUP = "overly-permissive"
SERVICES = ["route53profiles"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetProfile on a syntactically valid but nonexistent ProfileId is rejected with ResourceNotFoundException."""
    r53p = ctx.client("route53profiles")

    bogus_id = "rp-" + "0" * 20
    error = _client_error(lambda: r53p.get_profile(ProfileId=bogus_id))
    assert error["Code"] == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {error['Code']!r}"
    expected_message = f'[RSLVR-05007] Can\'t find the resource with ID "{bogus_id}".'
    assert error["Message"] == expected_message, f"expected {expected_message!r}, got {error['Message']!r}"

    # positive control: a real Profile in the same file is fetched successfully
    profile_id = _create_profile(ctx)

    fetched = r53p.get_profile(ProfileId=profile_id)["Profile"]
    assert fetched["Id"] == profile_id, f"expected {profile_id!r}, got {fetched.get('Id')!r}"


def _client_error(fn):
    """Call fn(); return its error (Code and Message). An unexpected SUCCESS raises, because an
    over-permissive target ACCEPTING an input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _create_profile(ctx) -> str:
    r53p = ctx.client("route53profiles")
    name = ctx.unique_name("sim2real-behav-profile-")
    deadline = time.monotonic() + min(200, ctx.time_left() or 200)
    while True:
        try:
            profile_id = r53p.create_profile(
                Name=name,
                ClientToken=ctx.unique_name("sim2real-behav-token-"),
                Tags=[{"Key": "sim2real-owner", "Value": "behavioral"}],
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
