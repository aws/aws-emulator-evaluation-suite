"""inference-profile-duplicate-name-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "inference-profile-duplicate-name-rejected"
GROUP = "state-machine"
SERVICES = ["bedrock"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Reusing a CreateInferenceProfile clientRequestToken with a different name returns the exact
    client-token ConflictException and creates no profile of that name, while replaying the same token
    and parameters returns the original ARN and one profile stays listed under the name."""
    bedrock = ctx.client("bedrock")
    source_model_arn = _pick_system_defined_inference_profile_arn(bedrock)
    token = ctx.unique_name("sim2real-infprofile-token-")
    profile_name = ctx.unique_name("sim2real-infprofile-dup-")

    first = bedrock.create_inference_profile(
        inferenceProfileName=profile_name,
        modelSource={"copyFrom": source_model_arn},
        clientRequestToken=token,
    )
    first_arn = first["inferenceProfileArn"]
    ctx.on_cleanup(
        lambda: _ignore_not_found(lambda: bedrock.delete_inference_profile(inferenceProfileIdentifier=first_arn))
    )

    other_name = ctx.unique_name("sim2real-infprofile-dup2-")
    code, message = _error(
        lambda: bedrock.create_inference_profile(
            inferenceProfileName=other_name,
            modelSource={"copyFrom": source_model_arn},
            clientRequestToken=token,
        )
    )
    assert code == "ConflictException", f"expected ConflictException, got {code!r}"
    expected_message = (
        "Your request contains different parameters from a previous request with the same client "
        "token. Retry the request with a different client token or with the same request "
        "parameters as the request that originally sent this client token."
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # effect absent: no profile was created under the differently-named request
    assert not _profiles_named(bedrock, other_name), (
        f"expected no profile named {other_name!r} after the rejected conflicting create"
    )

    # positive control: replaying the identical request (same token AND same params) is a
    # true idempotent no-op that returns the original profile rather than erroring
    replay = bedrock.create_inference_profile(
        inferenceProfileName=profile_name,
        modelSource={"copyFrom": source_model_arn},
        clientRequestToken=token,
    )
    assert replay["inferenceProfileArn"] == first_arn, (
        f"expected idempotent replay to echo {first_arn!r}, got {replay['inferenceProfileArn']!r}"
    )

    # terminal read: independent of both create calls above -- confirms the idempotent
    # replay did not silently materialize a second profile under the same name.
    confirmed = bedrock.get_inference_profile(inferenceProfileIdentifier=first_arn)
    assert confirmed["inferenceProfileName"] == profile_name, (
        f"expected {profile_name!r} at {first_arn!r}, got {confirmed['inferenceProfileName']!r}"
    )
    matches = _profiles_named(bedrock, profile_name)
    assert len(matches) == 1, f"expected exactly 1 profile named {profile_name!r}, got {len(matches)}"


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as e:
        err = e.response["Error"]
        return err["Code"], err.get("Message", "")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _ignore_not_found(fn) -> None:
    try:
        fn()
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _profiles_named(bedrock, profile_name: str) -> list:
    # An unfiltered ListInferenceProfiles does NOT surface
    # APPLICATION-type profiles (the kind CreateInferenceProfile makes here) at all --
    # typeEquals="APPLICATION" is required or every lookup silently returns zero rows.
    paginator = bedrock.get_paginator("list_inference_profiles")
    return [
        summary
        for page in paginator.paginate(typeEquals="APPLICATION")
        for summary in page.get("inferenceProfileSummaries", [])
        if summary.get("inferenceProfileName") == profile_name
    ]


# A pinned SYSTEM_DEFINED profile: the first listed one is whatever the region lists first, and
# copying from a profile whose model needs a per-account access grant is refused before the
# claim under test is reached.
_SOURCE_PROFILE_ID = "us.amazon.nova-micro-v1:0"


def _pick_system_defined_inference_profile_arn(bedrock) -> str:
    resp = bedrock.get_inference_profile(inferenceProfileIdentifier=_SOURCE_PROFILE_ID)
    assert resp["type"] == "SYSTEM_DEFINED", f"expected a SYSTEM_DEFINED source profile, got {resp['type']!r}"
    return resp["inferenceProfileArn"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

