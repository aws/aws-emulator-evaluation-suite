"""inference-profile-too-many-tags-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "inference-profile-too-many-tags-rejected"
GROUP = "state-machine"
SERVICES = ["bedrock"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateInferenceProfile with more than 50 tags is rejected with TooManyTagsException,
    no profile is created, and the same request with a valid tag count (positive control)
    succeeds."""
    bedrock = ctx.client("bedrock")
    source_model_arn = _pick_system_defined_inference_profile_arn(bedrock)

    too_many_name = ctx.unique_name("sim2real-infprofile-toomanytags-")
    too_many_tags = [{"key": f"k{i}", "value": f"v{i}"} for i in range(60)]

    code, message = _error(
        lambda: bedrock.create_inference_profile(
            inferenceProfileName=too_many_name,
            modelSource={"copyFrom": source_model_arn},
            tags=too_many_tags,
        )
    )
    assert code == "TooManyTagsException", f"expected TooManyTagsException, got {code!r}"
    expected_message = "You can assign a maximum of 50 tags to a resource"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # effect absent: the over-tagged profile was never created
    assert not _inference_profile_exists(bedrock, too_many_name), (
        f"{too_many_name} should not exist after a rejected CreateInferenceProfile"
    )

    # positive control: the same request with an acceptable tag count succeeds
    ok_name = ctx.unique_name("sim2real-infprofile-oktags-")
    ok_tags = [{"key": "purpose", "value": "sim2real-behavioral-check"}]
    created = bedrock.create_inference_profile(
        inferenceProfileName=ok_name, modelSource={"copyFrom": source_model_arn}, tags=ok_tags
    )
    profile_arn = created["inferenceProfileArn"]
    ctx.on_cleanup(
        lambda: _ignore_not_found(lambda: bedrock.delete_inference_profile(inferenceProfileIdentifier=profile_arn))
    )
    assert created["status"] == "ACTIVE", created

    # terminal read: independent of the mutating call, at the destination — the
    # profile is visible with the right name/status, and the tags it was created with
    # actually persisted.
    got = bedrock.get_inference_profile(inferenceProfileIdentifier=profile_arn)
    assert got["status"] == "ACTIVE", got
    assert got["inferenceProfileName"] == ok_name, got
    tags_on_profile = bedrock.list_tags_for_resource(resourceARN=profile_arn)["tags"]
    assert {(t["key"], t["value"]) for t in tags_on_profile} == {
        (t["key"], t["value"]) for t in ok_tags
    }, tags_on_profile


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


def _inference_profile_exists(bedrock, profile_name: str) -> bool:
    # An unfiltered ListInferenceProfiles omits APPLICATION-type profiles (the kind
    # CreateInferenceProfile makes), so the filter is required for this lookup to see one.
    paginator = bedrock.get_paginator("list_inference_profiles")
    for page in paginator.paginate(typeEquals="APPLICATION"):
        for summary in page.get("inferenceProfileSummaries", []):
            if summary.get("inferenceProfileName") == profile_name:
                return True
    return False


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

