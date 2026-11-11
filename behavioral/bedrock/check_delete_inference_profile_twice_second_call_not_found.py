"""delete-inference-profile-twice-second-call-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-inference-profile-twice-second-call-not-found"
GROUP = "overly-permissive"
SERVICES = ["bedrock"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A second DeleteInferenceProfile on an already-deleted application inference profile
    returns ResourceNotFoundException instead of a permissive 200."""
    bedrock = ctx.client("bedrock")

    profile_arn = _create_application_profile(ctx, bedrock)

    # Positive control: deleting a live profile succeeds.
    bedrock.delete_inference_profile(inferenceProfileIdentifier=profile_arn)

    # Genuinely gone, not just marked pending-delete.
    gone = _error(lambda: bedrock.get_inference_profile(inferenceProfileIdentifier=profile_arn))
    gone_expected = ("ResourceNotFoundException", "Inference profile not found.")
    assert gone == gone_expected, (
        f"expected the profile to be gone after delete with {gone_expected!r}, got {gone!r}"
    )

    got = _error(lambda: bedrock.delete_inference_profile(inferenceProfileIdentifier=profile_arn))
    expected = ("ResourceNotFoundException", "Inference profile not found.")
    assert got == expected, f"expected {expected!r}, got {got!r}"


def _create_application_profile(ctx, bedrock) -> str:
    """Create an application inference profile copied from a SYSTEM_DEFINED one; return its ARN.
    Copying is refused with AccessDeniedException for a model the account cannot access, so
    candidates are tried in listing order until one is copyable."""
    resp = bedrock.list_inference_profiles(typeEquals="SYSTEM_DEFINED", maxResults=50)
    candidates = [s["inferenceProfileArn"] for s in resp.get("inferenceProfileSummaries", [])]
    assert candidates, "expected at least one SYSTEM_DEFINED inference profile in this account/region"
    refusals = []
    for source_arn in candidates:
        try:
            created = bedrock.create_inference_profile(
                inferenceProfileName=ctx.unique_name("sim2real-infprof-"),
                modelSource={"copyFrom": source_arn},
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException":
                raise
            refusals.append(source_arn)
            continue
        profile_arn = created["inferenceProfileArn"]
        ctx.on_cleanup(lambda: _safe_delete(bedrock, profile_arn))
        return profile_arn
    raise AssertionError(f"no SYSTEM_DEFINED inference profile is copyable here; all refused: {refusals}")


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message", "")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _safe_delete(bedrock, profile_arn: str) -> None:
    try:
        bedrock.delete_inference_profile(inferenceProfileIdentifier=profile_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
