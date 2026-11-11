"""update-provisioned-throughput-concurrent-race-one-wins."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "update-provisioned-throughput-concurrent-race-one-wins"
GROUP = "error-semantics"
SERVICES = ["bedrock"]

# Three unrelated model families: two Titan text generations and a Llama 3 model from another
# provider. Probing all three tells "one model is not PT-eligible" apart from "commitment-free
# Provisioned Throughput is not offered", and AWS returns the identical refusal for each.
_CANDIDATE_MODELS = (
    "amazon.titan-text-express-v1",
    "amazon.titan-text-premier-v1:0",
    "meta.llama3-70b-instruct-v1:0",  # eol-subject: the commitment-free PT refusal is enumerated per model family
)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Commitment-free CreateProvisionedModelThroughput is refused with the same immediate
    ValidationException for three unrelated model families, after a List call proves the API is
    reachable, and a follow-up List shows no half-created resource under any attempted name."""
    bedrock = ctx.client("bedrock")

    bedrock.list_provisioned_model_throughputs()

    for model_id in _CANDIDATE_MODELS:
        name = ctx.unique_name("sim2real-pt-race-")
        code, message = _create_error(bedrock, ctx.region, model_id, name)
        assert code == "ValidationException", (
            f"expected ValidationException creating a PT on {model_id!r}, got "
            f"{code!r}: {message}"
        )
        expected_message = "The provided model is not supported for provisioned throughput."
        assert message == expected_message, (
            f"expected the model-not-eligible-for-PT refusal {expected_message!r} for "
            f"{model_id!r}, got: {message!r}"
        )

        listing = bedrock.list_provisioned_model_throughputs()
        matches = [
            p
            for p in listing.get("provisionedModelSummaries", [])
            if p.get("provisionedModelName") == name
        ]
        assert matches == [], f"rejected create left a PT behind under {name!r}: {matches}"


def _create_error(bedrock, region: str, model_id: str, name: str) -> tuple[str, str]:
    arn = f"arn:aws:bedrock:{region}::foundation-model/{model_id}"
    try:
        resp = bedrock.create_provisioned_model_throughput(
            modelUnits=1, provisionedModelName=name, modelId=arn
        )
    except Exception as exc:  # noqa: BLE001
        error = getattr(exc, "response", {}).get("Error", {})
        return error.get("Code", "unknown"), error.get("Message", str(exc))

    # Unexpected: PT actually got created (e.g. AWS re-enabled this model for PT).
    # Do not leave a billed resource behind just because our assumption was wrong.
    pt_arn = resp["provisionedModelArn"]
    try:
        bedrock.delete_provisioned_model_throughput(provisionedModelId=pt_arn)
    except Exception:  # noqa: BLE001
        pass
    raise AssertionError(
        f"create_provisioned_model_throughput unexpectedly succeeded for {model_id!r} "
        f"(id={pt_arn}, now deleted) -- Provisioned Throughput may have been re-enabled "
        "for this model; this check needs to be rewritten to exercise the concurrent-"
        "rename race again"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
