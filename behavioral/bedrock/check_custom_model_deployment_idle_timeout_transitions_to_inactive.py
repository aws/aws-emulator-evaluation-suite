"""custom-model-deployment-idle-timeout-transitions-to-inactive."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "custom-model-deployment-idle-timeout-transitions-to-inactive"
GROUP = "visibility-timeout-ttl"
SERVICES = ["bedrock"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateCustomModelDeployment rejects a modelArn naming an unknown foundation model.

    The ValidationException is synchronous and exact, and no deployment is persisted: Get on the
    name is invalid and List omits it. ListFoundationModels is the healthy-account control.
    """
    bedrock = ctx.client("bedrock")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    # Positive control: the account/credentials are healthy for Bedrock.
    catalog = bedrock.list_foundation_models()
    summaries = catalog.get("modelSummaries")
    assert summaries, (
        f"positive control: expected ListFoundationModels to return a non-empty catalog "
        f"for a healthy account, got {catalog!r}"
    )

    nonexistent_model_arn = (
        f"arn:aws:bedrock:{ctx.region}:{account_id}:custom-model/sim2real-noexist.v1/abcdef012345"
    )
    deployment_name = ctx.unique_name("sim2real-cmd-")

    got = _error_code(
        lambda: bedrock.create_custom_model_deployment(
            modelDeploymentName=deployment_name, modelArn=nonexistent_model_arn
        )
    )
    expected = (
        "ValidationException",
        "The foundation model 'sim2real-noexist.v1' for custom model is not a valid foundation model",
    )
    assert got == expected, (
        f"expected CreateCustomModelDeployment to reject a modelArn naming an unrecognized "
        f"foundation model synchronously with {expected!r}, got {got!r}"
    )

    # Effect absent: no deployment record was persisted from the rejected request.
    # (Empirically, GetCustomModelDeployment on a bare name that was never
    # created returns ValidationException, not ResourceNotFoundException.)
    get_got = _error_code(
        lambda: bedrock.get_custom_model_deployment(customModelDeploymentIdentifier=deployment_name)
    )
    get_expected = ("ValidationException", "The provided custom model deployment identifier is invalid.")
    assert get_got == get_expected, (
        f"expected GetCustomModelDeployment on a bare name that was never created to "
        f"return {get_expected!r}, got {get_got!r}"
    )

    # Structural assertion on the response body (not merely a 200 status): the
    # list call must return a well-formed summaries collection that does not
    # include our never-created deployment.
    listed = bedrock.list_custom_model_deployments()
    assert "modelDeploymentSummaries" in listed, f"malformed ListCustomModelDeployments response: {listed!r}"
    assert not any(
        summary.get("modelDeploymentName") == deployment_name
        for summary in listed["modelDeploymentSummaries"]
    ), f"expected no summary for the never-created deployment {deployment_name!r}, got {listed!r}"


def _error_code(fn):
    try:
        result = fn()
    except ClientError as err:
        error = err.response["Error"]
        return error["Code"], error.get("Message", "")
    raise AssertionError(f"expected a ClientError but the call succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
