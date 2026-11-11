"""delete-inference-profile-referenced-by-prompt-router-accepted."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "delete-inference-profile-referenced-by-prompt-router-accepted"
GROUP = "overly-permissive"
SERVICES = ["bedrock"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteInferenceProfile succeeds while a PromptRouter still targets the profile, and the
    router stays AVAILABLE with its now-dangling fallbackModel reference unchanged.

    Reference: https://docs.aws.amazon.com/bedrock/latest/APIReference/API_PromptRouterTargetModel.html
    """
    bedrock = ctx.client("bedrock")

    router_model_arn, profile_base_model_arn = _pick_prompt_router_model_pair(bedrock)

    profile_resp = bedrock.create_inference_profile(
        inferenceProfileName=ctx.unique_name("sim2real-bedrock-profile-"),
        modelSource={"copyFrom": profile_base_model_arn},
        tags=[{"key": "sim2real", "value": CHECK}],
    )
    profile_arn = profile_resp["inferenceProfileArn"]
    ctx.on_cleanup(lambda: _safe_delete_profile(bedrock, profile_arn))

    router_resp = bedrock.create_prompt_router(
        promptRouterName=ctx.unique_name("sim2real-bedrock-router-"),
        # fallbackModel must itself be present in `models`, and the profile's underlying
        # model must differ from router_model_arn or the two are rejected as duplicates.
        models=[{"modelArn": router_model_arn}, {"modelArn": profile_arn}],
        fallbackModel={"modelArn": profile_arn},
        routingCriteria={"responseQualityDifference": 10.0},
        tags=[{"key": "sim2real", "value": CHECK}],
    )
    router_arn = router_resp["promptRouterArn"]
    ctx.on_cleanup(lambda: _safe_delete_router(bedrock, router_arn))

    # Confirm the router genuinely targets the profile before deleting it out from under it.
    router_before = bedrock.get_prompt_router(promptRouterArn=router_arn)
    assert router_before.get("fallbackModel", {}).get("modelArn") == profile_arn, (
        f"router setup did not actually target the profile as fallbackModel: "
        f"{router_before.get('fallbackModel')!r}"
    )

    bedrock.delete_inference_profile(inferenceProfileIdentifier=profile_arn)
    _wait_for_profile_gone(bedrock, profile_arn, timeout_s=60)

    router_after = bedrock.get_prompt_router(promptRouterArn=router_arn)
    assert router_after["status"] == "AVAILABLE", (
        f"router should be unaffected by the profile's deletion, got status "
        f"{router_after.get('status')!r}"
    )
    assert router_after.get("fallbackModel", {}).get("modelArn") == profile_arn, (
        f"router's stored fallbackModel reference changed after the profile it points to was "
        f"deleted: {router_after.get('fallbackModel')!r}"
    )


# Prompt routing accepts only specific foundation models (Titan Text and Nova Micro are rejected
# as "not supported"), so eligible pairs cannot be derived from list_foundation_models alone.
_ROUTER_ELIGIBLE_MODEL_PAIRS = (
    ("meta.llama3-1-70b-instruct-v1:0", "meta.llama3-1-8b-instruct-v1:0"),
    ("amazon.nova-pro-v1:0", "amazon.nova-lite-v1:0"),
)


def _pick_prompt_router_model_pair(bedrock) -> tuple[str, str]:
    resp = bedrock.list_foundation_models(byInferenceType="ON_DEMAND", byOutputModality="TEXT")
    by_id = {m["modelId"]: m["modelArn"] for m in resp.get("modelSummaries", [])}
    for router_model_id, profile_base_model_id in _ROUTER_ELIGIBLE_MODEL_PAIRS:
        if router_model_id in by_id and profile_base_model_id in by_id:
            return by_id[router_model_id], by_id[profile_base_model_id]
    raise AssertionError(
        "none of the known prompt-router-eligible model pairs "
        f"{_ROUTER_ELIGIBLE_MODEL_PAIRS!r} are available in this account/region; available "
        f"ON_DEMAND text model ids: {sorted(by_id)!r}"
    )


def _safe_delete_profile(bedrock, profile_arn: str) -> None:
    try:
        bedrock.delete_inference_profile(inferenceProfileIdentifier=profile_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _safe_delete_router(bedrock, router_arn: str) -> None:
    try:
        bedrock.delete_prompt_router(promptRouterArn=router_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _wait_for_profile_gone(bedrock, profile_arn: str, timeout_s: float) -> None:
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            bedrock.get_inference_profile(inferenceProfileIdentifier=profile_arn)
        except ClientError as err:
            if err.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(2)
    raise AssertionError("inference profile was not deleted within the timeout")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
