"""delete-inference-profile-not-found-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-inference-profile-not-found-rejected"
GROUP = "error-semantics"
SERVICES = ["bedrock"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Deleting a real application inference profile succeeds, after which GetInferenceProfile and a
    second DeleteInferenceProfile on its ARN both return ResourceNotFoundException 'Inference profile
    not found.'
    """
    bedrock = ctx.client("bedrock")
    profile_arn = _create_application_profile(ctx, bedrock)

    # positive control: deleting a real, existing profile succeeds
    bedrock.delete_inference_profile(inferenceProfileIdentifier=profile_arn)

    gone = _error(lambda: bedrock.get_inference_profile(inferenceProfileIdentifier=profile_arn))
    gone_expected = ("ResourceNotFoundException", "Inference profile not found.")
    assert gone == gone_expected, f"expected the profile to be gone after delete with {gone_expected!r}, got {gone!r}"

    # negative: deleting the deleted profile is rejected, not a silent no-op success
    redelete = _error(lambda: bedrock.delete_inference_profile(inferenceProfileIdentifier=profile_arn))
    redelete_expected = ("ResourceNotFoundException", "Inference profile not found.")
    assert redelete == redelete_expected, (
        f"expected a second delete of the same (now-gone) profile to be rejected with "
        f"{redelete_expected!r}, got {redelete!r}"
    )


def _error(fn):
    """Call fn() and return its error (code, message); a success raises, as the call must be refused."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message", "")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _safe(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _create_application_profile(ctx, bedrock) -> str:
    """Create an application inference profile copied from a SYSTEM_DEFINED one, register its
    cleanup, and return its ARN. Copying from the profile of a model the account cannot access is
    refused with AccessDeniedException, so the candidates are tried in listing order until one is
    copyable."""
    resp = bedrock.list_inference_profiles(typeEquals="SYSTEM_DEFINED", maxResults=50)
    candidates = [s["inferenceProfileArn"] for s in resp.get("inferenceProfileSummaries", [])]
    assert candidates, "expected at least one SYSTEM_DEFINED inference profile in this account/region"
    refusals = []
    for source_arn in candidates:
        try:
            created = bedrock.create_inference_profile(
                inferenceProfileName=ctx.unique_name("sim2real-bedrock-ip-"),
                modelSource={"copyFrom": source_arn},
                tags=[{"key": "sim2real", "value": CHECK}],
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException":
                raise
            refusals.append(source_arn)
            continue
        profile_arn = created["inferenceProfileArn"]
        ctx.on_cleanup(
            lambda: _safe(lambda: bedrock.delete_inference_profile(inferenceProfileIdentifier=profile_arn))
        )
        return profile_arn
    raise AssertionError(f"no SYSTEM_DEFINED inference profile is copyable here; all refused: {refusals}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
