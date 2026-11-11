"""deregister-marketplace-endpoint-missing-returns-notfound."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deregister-marketplace-endpoint-missing-returns-notfound"
GROUP = "error-semantics"
SERVICES = ["bedrock"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeregisterMarketplaceModelEndpoint on an unregistered ARN returns ResourceNotFoundException.

    The service checks registration before authorization, so the miss is reported, not denied.
    """
    bedrock = ctx.client("bedrock")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    # Positive control: a Guardrail create+delete proves Bedrock writes are allowed here.
    # A real marketplace endpoint needs a Marketplace subscription and a SageMaker endpoint.
    guardrail_name = ctx.unique_name("sim2real-bedrock-ctrl-gr-")
    created = bedrock.create_guardrail(
        name=guardrail_name,
        blockedInputMessaging="Sorry, this input is blocked.",
        blockedOutputsMessaging="Sorry, this output is blocked.",
        wordPolicyConfig={"wordsConfig": [{"text": "sim2realforbiddenword"}]},
    )
    guardrail_id = created["guardrailId"]
    ctx.on_cleanup(lambda: _safe(lambda: bedrock.delete_guardrail(guardrailIdentifier=guardrail_id)))
    bedrock.delete_guardrail(guardrailIdentifier=guardrail_id)

    # A registered marketplace endpoint's ARN is the underlying SageMaker endpoint ARN.
    bogus_endpoint_arn = (
        f"arn:aws:sagemaker:{ctx.region}:{account_id}:endpoint/"
        f"{ctx.unique_name('sim2real-bedrock-noendpoint-')}"
    )

    got = _error_code_and_message(
        lambda: bedrock.deregister_marketplace_model_endpoint(endpointArn=bogus_endpoint_arn)
    )
    expected = ("ResourceNotFoundException", "Bedrock Resource not found.")
    assert got == expected, f"expected {expected!r}, got {got!r}"

    # The rejected deregister must not make the ARN appear.
    listed = bedrock.list_marketplace_model_endpoints().get("marketplaceModelEndpoints", [])
    matching = [e for e in listed if e["endpointArn"] == bogus_endpoint_arn]
    assert matching == [], f"deregistering a never-registered ARN must not create it, found: {matching}"


def _error_code_and_message(fn):
    try:
        fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message", "")
    raise AssertionError("expected deregister_marketplace_model_endpoint to raise, but it succeeded")


def _safe(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
