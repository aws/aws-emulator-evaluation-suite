"""register-marketplace-endpoint-invalid-arn-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "register-marketplace-endpoint-invalid-arn-rejected"
GROUP = "overly-permissive"
SERVICES = ["bedrock"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """RegisterMarketplaceModelEndpoint with a modelSourceIdentifier off the hub-content ARN pattern
    returns the exact pattern ValidationException, a well-formed but missing hub-content ARN returns
    ResourceNotFoundException naming the hub content, and no endpoint is registered."""
    bedrock = ctx.client("bedrock")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    endpoint_identifier = (
        f"arn:aws:sagemaker:{ctx.region}:{account_id}:endpoint/"
        f"{ctx.unique_name('sim2real-noendpoint-')}"
    )

    malformed_source = "not-an-arn-at-all"
    code, message = _error(
        lambda: bedrock.register_marketplace_model_endpoint(
            endpointIdentifier=endpoint_identifier, modelSourceIdentifier=malformed_source
        )
    )
    assert code == "ValidationException", (
        f"expected ValidationException for a malformed modelSourceIdentifier, got {code!r}: {message!r}"
    )
    assert message == "1 validation error detected: Value at 'modelSourceIdentifier' failed to satisfy constraint: Member must satisfy regular expression pattern: .*arn:aws:sagemaker:.*:hub-content/SageMakerPublicHub/Model/.*", f"unexpected rejection message: {message!r}"

    # Positive control (format-validation depth, not full success): a
    # well-formed hub-content ARN that merely does not exist passes the same
    # format check and is rejected with a *different*, resource-lookup error
    # rather than being blanket-rejected as malformed. A 200 success here would
    # need a subscribed SageMaker Marketplace model endpoint.
    missing_model_name = ctx.unique_name("sim2real-nomodel-")
    well_formed_but_missing = (
        f"arn:aws:sagemaker:{ctx.region}:aws:hub-content/SageMakerPublicHub/Model/"
        f"{missing_model_name}/1.0.0"
    )
    control_code, control_message = _error(
        lambda: bedrock.register_marketplace_model_endpoint(
            endpointIdentifier=endpoint_identifier, modelSourceIdentifier=well_formed_but_missing
        )
    )
    assert control_code == "ResourceNotFoundException", f"{control_code}: {control_message!r}"
    assert control_message == f"Hub content with name {missing_model_name} does not exist.", (
        f"unexpected rejection message: {control_message!r}"
    )

    # Effect absent: neither the malformed nor the well-formed-but-missing
    # attempt actually registered anything under our endpoint identifier.
    listed = bedrock.list_marketplace_model_endpoints().get("marketplaceModelEndpoints", [])
    assert not any(e.get("endpointArn") == endpoint_identifier for e in listed), (
        f"expected no marketplace endpoint to have been registered for {endpoint_identifier!r}, "
        f"found it in {listed!r}"
    )


def _error(fn):
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
