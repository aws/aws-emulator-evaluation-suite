"""put-use-case-for-model-access-server-recorded."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-use-case-for-model-access-server-recorded"
GROUP = "server-side"
SERVICES = ["bedrock"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:bedrock-model-access-use-case")
def run(ctx) -> None:
    """PutUseCaseForModelAccess with a one-field form is refused with ValidationException 'Invalid form
    data.' (or an AccessDeniedException naming Internal Account), and GetUseCaseForModelAccess shows
    the refused write left no trace, while ListFoundationModels still returns models.
    """
    bedrock = ctx.client("bedrock")

    positive_control = bedrock.list_foundation_models()
    assert positive_control.get("modelSummaries"), (
        "positive control failed: ListFoundationModels returned no models, so bedrock "
        "connectivity/credentials are not healthy on this account independent of the "
        "PutUseCaseForModelAccess refusal under test"
    )

    original_bytes: bytes | None = None
    original_not_found = False
    try:
        original_bytes = bedrock.get_use_case_for_model_access()["formData"]
    except ClientError as err:
        assert err.response["Error"]["Code"] == "ResourceNotFoundException", (
            f"expected ResourceNotFoundException for a never-registered account, got "
            f"{err.response['Error']['Code']}"
        )
        original_not_found = True

    marker = ctx.unique_name("sim2real-usecase-")
    payload = f'{{"companyName": "{marker}"}}'.encode("utf-8")

    try:
        bedrock.put_use_case_for_model_access(formData=payload)
    except ClientError as err:
        code = err.response["Error"]["Code"]
        message = err.response["Error"].get("Message", "")
        if code == "ValidationException":
            assert message == "Invalid form data.", (
                f"expected the exact generic refusal 'Invalid form data.', got {message!r}"
            )
        elif code == "AccessDeniedException" and "Internal Account" in message:
            pass
        else:
            raise AssertionError(
                "expected ValidationException('Invalid form data.') or an Internal-Account "
                f"AccessDeniedException, got {code}: {message!r}"
            ) from err
    else:
        raise AssertionError(
            "PutUseCaseForModelAccess unexpectedly SUCCEEDED on this account -- real AWS no "
            "longer refuses this call the way every prior replay of this check has observed; "
            "the durable-persistence contract is exercisable again and this check should be "
            "rewritten to assert Put/Get persistence instead of the refusal"
        )

    # Effect-absent: the refused write must have left no trace, via an independent read.
    if original_not_found:
        try:
            bedrock.get_use_case_for_model_access()
        except ClientError as err:
            assert err.response["Error"]["Code"] == "ResourceNotFoundException", (
                f"expected the pre-Put ResourceNotFoundException to persist after the refused "
                f"Put, got {err.response['Error']['Code']}"
            )
            assert err.response["Error"]["Message"] == "You have not filled out the request form. Fill out the form before getting access.", (
                f'expected the exact ResourceNotFoundException message AWS returns, got {err.response["Error"]["Message"]!r}'
            )
        else:
            raise AssertionError(
                "GetUseCaseForModelAccess started returning a form despite Put being refused"
            )
    else:
        after = bedrock.get_use_case_for_model_access()["formData"]
        assert after == original_bytes, (
            "GetUseCaseForModelAccess changed after a refused Put: "
            f"{after!r} != original {original_bytes!r}"
        )
        assert marker.encode("utf-8") not in after, (
            f"our marker {marker!r} leaked into the recorded form despite Put being refused"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
