"""delete-inference-profile-missing-conflict-not-notfound."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-inference-profile-missing-conflict-not-notfound"
GROUP = "error-semantics"
SERVICES = ["bedrock"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteInferenceProfile and GetInferenceProfile on a nonexistent profile return
    ResourceNotFoundException 'Inference profile not found.', not ConflictException, while a real
    application inference profile deletes and then reads back with the same not-found answer.
    """
    bedrock = ctx.client("bedrock")
    bogus_id = ctx.unique_name("sim2real-bedrock-noprofile-")

    got = _error(lambda: bedrock.delete_inference_profile(inferenceProfileIdentifier=bogus_id))
    expected = ("ResourceNotFoundException", "Inference profile not found.")
    assert got == expected, f"expected {expected!r}, got {got!r}"

    # effect absent: no profile was silently created as a side effect of the delete
    get_got = _error(lambda: bedrock.get_inference_profile(inferenceProfileIdentifier=bogus_id))
    get_expected = ("ResourceNotFoundException", "Inference profile not found.")
    assert get_got == get_expected, (
        f"expected the bogus profile identifier to remain absent with {get_expected!r}, got {get_got!r}"
    )

    # Positive control: the same operation on a real application inference profile succeeds,
    # so "does not exist" is distinguished from "exists and was deleted". The profile copies a
    # system-defined one discovered at runtime, whichever models the account has enabled.
    profile_arn = _create_application_profile(ctx, bedrock)

    bedrock.delete_inference_profile(inferenceProfileIdentifier=profile_arn)

    final = _error(lambda: bedrock.get_inference_profile(inferenceProfileIdentifier=profile_arn))
    final_expected = ("ResourceNotFoundException", "Inference profile not found.")
    assert final == final_expected, (
        f"expected the real profile to be gone after delete with {final_expected!r}, got {final!r}"
    )


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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
