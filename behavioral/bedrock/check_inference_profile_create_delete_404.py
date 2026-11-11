"""inference-profile-create-delete-404."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "inference-profile-create-delete-404"
GROUP = "state-machine"
SERVICES = ["bedrock"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An inference profile copied from a foundation model is ACTIVE on create and get and lists that
    model; after DeleteInferenceProfile, GetInferenceProfile and a second delete both return
    ResourceNotFoundException 'Inference profile not found.'"""
    bedrock = ctx.client("bedrock")
    source_model_arn = _first_on_demand_text_model_arn(bedrock)

    name = ctx.unique_name("sim2real-infprofile-")
    create_resp = bedrock.create_inference_profile(
        inferenceProfileName=name,
        modelSource={"copyFrom": source_model_arn},
        tags=[{"key": "sim2real", "value": "inference-profile-create-delete-404"}],
    )
    profile_arn = create_resp["inferenceProfileArn"]
    ctx.on_cleanup(lambda: _best_effort_delete(bedrock, profile_arn))
    # ACTIVE is documented as the only value InferenceProfileStatus takes on success.
    assert create_resp["status"] == "ACTIVE", (
        f"expected ACTIVE status on create, got {create_resp['status']!r}"
    )

    got = bedrock.get_inference_profile(inferenceProfileIdentifier=profile_arn)
    assert got["inferenceProfileName"] == name, (
        f"expected inferenceProfileName {name!r}, got {got['inferenceProfileName']!r}"
    )
    assert got["status"] == "ACTIVE", f"expected ACTIVE status on get, got {got['status']!r}"
    model_arns = [m.get("modelArn") for m in got["models"]]
    assert source_model_arn in model_arns, (
        f"expected source model {source_model_arn!r} among profile models, got {model_arns!r}"
    )

    bedrock.delete_inference_profile(inferenceProfileIdentifier=profile_arn)

    code, message = _error(
        lambda: bedrock.get_inference_profile(inferenceProfileIdentifier=profile_arn)
    )
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException reading the deleted profile, got {code!r}"
    )
    expected_get_message = "Inference profile not found."
    assert message == expected_get_message, (
        f"expected message {expected_get_message!r} reading the deleted profile, got {message!r}"
    )

    # The dead identifier must also reject a mutation, not just a read: a second delete is
    # not a permissive no-op success.
    second_delete_code, second_delete_message = _error(
        lambda: bedrock.delete_inference_profile(inferenceProfileIdentifier=profile_arn)
    )
    assert second_delete_code == "ResourceNotFoundException", (
        f"expected a second delete of the same dead profile to be rejected with "
        f"ResourceNotFoundException, got {second_delete_code!r}"
    )
    expected_delete_message = "Inference profile not found."
    assert second_delete_message == expected_delete_message, (
        f"expected message {expected_delete_message!r} on the second delete, "
        f"got {second_delete_message!r}"
    )


def _error(fn):
    """Call fn() and return its error (code, message); a success raises, as the call must be refused."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        err = e.response["Error"]
        return err["Code"], err.get("Message", "")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _best_effort_delete(bedrock, profile_arn):
    from botocore.exceptions import ClientError

    try:
        bedrock.delete_inference_profile(inferenceProfileIdentifier=profile_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _first_on_demand_text_model_arn(bedrock):
    resp = bedrock.list_foundation_models(byOutputModality="TEXT", byInferenceType="ON_DEMAND")
    summaries = [
        m
        for m in resp.get("modelSummaries", [])
        if m.get("modelLifecycle", {}).get("status") == "ACTIVE"
    ]
    if not summaries:
        raise AssertionError(
            "no ACTIVE on-demand text foundation model available in this account/region "
            "to use as an inference-profile source"
        )
    return summaries[0]["modelArn"]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
