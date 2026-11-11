"""prompt-router-create-delete-404."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "prompt-router-create-delete-404"
GROUP = "state-machine"
SERVICES = ["bedrock"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreatePromptRouter creates an AVAILABLE, retrievable router; DeletePromptRouter
    removes it so a subsequent GetPromptRouter raises ResourceNotFoundException."""
    bedrock = ctx.client("bedrock")
    model_arns = _two_on_demand_text_model_arns(bedrock)

    name = ctx.unique_name("sim2real-promptrouter-")
    create_resp = bedrock.create_prompt_router(
        promptRouterName=name,
        models=[{"modelArn": model_arns[0]}, {"modelArn": model_arns[1]}],
        routingCriteria={"responseQualityDifference": 10.0},
        fallbackModel={"modelArn": model_arns[0]},
    )
    router_arn = create_resp["promptRouterArn"]
    ctx.on_cleanup(lambda: _best_effort_delete(bedrock, router_arn))

    got = bedrock.get_prompt_router(promptRouterArn=router_arn)
    assert got["promptRouterName"] == name
    # PromptRouterStatus is documented as always AVAILABLE.
    assert got["status"] == "AVAILABLE"
    assert got["type"] == "custom"

    bedrock.delete_prompt_router(promptRouterArn=router_arn)

    code, message = _error(lambda: bedrock.get_prompt_router(promptRouterArn=router_arn))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}"
    expected_message = f"Cannot find prompt router {router_arn}."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        err = e.response["Error"]
        return err["Code"], err.get("Message", "")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _best_effort_delete(bedrock, router_arn):
    from botocore.exceptions import ClientError

    try:
        bedrock.delete_prompt_router(promptRouterArn=router_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _two_on_demand_text_model_arns(bedrock):
    """Return two same-provider foundation-model ARNs that intelligent prompt routing supports.

    CreatePromptRouter rejects a mixed-provider pair, so the pair is pinned to one provider.
    The pair is not filtered through ListFoundationModels(byInferenceType="ON_DEMAND"): in
    regions where Nova is served only through inference profiles that filter drops both
    models although CreatePromptRouter accepts their foundation-model ARNs.
    """
    region = bedrock.meta.region_name
    arn_prefix = f"arn:aws:bedrock:{region}::foundation-model/"
    return [arn_prefix + "amazon.nova-lite-v1:0", arn_prefix + "amazon.nova-pro-v1:0"]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
