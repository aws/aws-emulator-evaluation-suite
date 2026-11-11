"""inference-profile-lifecycle."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "inference-profile-lifecycle"
GROUP = "state-machine"
SERVICES = ["bedrock"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateInferenceProfile reaches Active state and DeleteInferenceProfile transitions
    it to not-found on subsequent Get."""
    bedrock = ctx.client("bedrock")
    profile_name = ctx.unique_name("sim2real-infprofile-")
    # Copy from a real, region-available system-defined (cross-region) inference profile
    # rather than a raw foundation-model ARN, which requires per-model EULA/access grants
    # that vary by account and would make this check flaky for reasons unrelated to the
    # inference-profile lifecycle itself.
    source_model_arn = _pick_system_defined_inference_profile_arn(bedrock)

    created = bedrock.create_inference_profile(
        inferenceProfileName=profile_name,
        modelSource={"copyFrom": source_model_arn},
        tags=[{"key": "sim2real", "value": "inference-profile-lifecycle"}],
    )
    profile_arn = created["inferenceProfileArn"]
    assert created["status"] == "ACTIVE", f"expected ACTIVE on create, got {created['status']!r}"
    ctx.on_cleanup(
        lambda: _ignore_not_found(
            lambda: bedrock.delete_inference_profile(inferenceProfileIdentifier=profile_arn)
        )
    )

    got = bedrock.get_inference_profile(inferenceProfileIdentifier=profile_arn)
    assert got["inferenceProfileArn"] == profile_arn, (
        f"expected {profile_arn!r}, got {got['inferenceProfileArn']!r}"
    )
    assert got["inferenceProfileName"] == profile_name, (
        f"expected {profile_name!r}, got {got['inferenceProfileName']!r}"
    )
    assert got["status"] == "ACTIVE", f"expected ACTIVE on get, got {got['status']!r}"

    bedrock.delete_inference_profile(inferenceProfileIdentifier=profile_arn)

    def _probe():
        return _error_code(lambda: bedrock.get_inference_profile(inferenceProfileIdentifier=profile_arn))

    code = _poll_until(_probe, lambda c: c is not None, timeout_s=60.0, interval_s=2.0)
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException after delete, got {code!r}"
    )


def _error_code(fn):
    try:
        fn()
        return None
    except ClientError as e:
        return e.response["Error"]["Code"]


def _ignore_not_found(fn) -> None:
    try:
        fn()
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _pick_system_defined_inference_profile_arn(bedrock) -> str:
    resp = bedrock.list_inference_profiles(typeEquals="SYSTEM_DEFINED", maxResults=1)
    summaries = resp.get("inferenceProfileSummaries", [])
    assert summaries, "expected at least one SYSTEM_DEFINED inference profile in this region"
    return summaries[0]["inferenceProfileArn"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
