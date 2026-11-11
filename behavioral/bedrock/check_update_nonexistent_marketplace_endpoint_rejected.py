"""update-nonexistent-marketplace-endpoint-rejected."""
from __future__ import annotations

import json

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "update-nonexistent-marketplace-endpoint-rejected"
GROUP = "overly-permissive"
SERVICES = ["bedrock"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateMarketplaceModelEndpoint on an unregistered ARN is ResourceNotFound, creates nothing.

    Get on the same ARN is a ValidationException, and the endpoint stays absent from the list.
    """
    bedrock = ctx.client("bedrock")
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    endpoint_name = ctx.unique_name("sim2real-never-registered-")
    endpoint_arn = f"arn:aws:sagemaker:{ctx.region}:{account_id}:endpoint/{endpoint_name}"

    role_name = ctx.unique_name("sim2real-mme-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "sagemaker.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role_best_effort(ctx, role_name))

    code, message = _error_code_and_message(lambda: bedrock.update_marketplace_model_endpoint(
        endpointArn=endpoint_arn,
        endpointConfig={
            "sageMaker": {
                "initialInstanceCount": 1,
                "instanceType": "ml.m5.xlarge",
                "executionRole": role_arn,
            }
        },
    ))
    assert code == "ResourceNotFoundException", (
        f"expected the update to be rejected with ResourceNotFoundException, got {code!r}: {message}"
    )
    assert message == "Bedrock Resource not found.", (
        f"expected AWS's exact not-found message, got {message!r}"
    )


    listed = bedrock.list_marketplace_model_endpoints().get("marketplaceModelEndpoints", [])
    matching = [e for e in listed if e["endpointArn"] == endpoint_arn]
    assert matching == [], f"update on a nonexistent endpoint must not create it, found: {matching}"

    get_code, get_message = _error_code_and_message(
        lambda: bedrock.get_marketplace_model_endpoint(endpointArn=endpoint_arn)
    )
    assert get_code == "ValidationException", (
        f"expected Get on a never-registered endpoint to be rejected with ValidationException, "
        f"got {get_code!r}: {get_message}"
    )
    expected_get_message = f'Could not find endpoint "{endpoint_name}".'
    assert get_message == expected_get_message, (
        f"expected the exact message {expected_get_message!r}, got: {get_message!r}"
    )

    # Positive control: Bedrock control-plane calls work, so the rejection is not blanket denial.
    # A guardrail stands in because a real marketplace endpoint needs a Marketplace subscription.
    guardrail_name = ctx.unique_name("sim2real-bedrock-ctrl-gr-")
    created_guardrail = bedrock.create_guardrail(
        name=guardrail_name,
        blockedInputMessaging="Sorry, this input is blocked.",
        blockedOutputsMessaging="Sorry, this output is blocked.",
        wordPolicyConfig={"wordsConfig": [{"text": "sim2realforbiddenword"}]},
    )
    guardrail_id = created_guardrail["guardrailId"]
    ctx.on_cleanup(lambda: _safe(lambda: bedrock.delete_guardrail(guardrailIdentifier=guardrail_id)))
    bedrock.delete_guardrail(guardrailIdentifier=guardrail_id)




def _error_code_and_message(fn):
    """The AWS (code, message) raised by fn(), or a loud failure if it unexpectedly SUCCEEDS."""
    try:
        result = fn()
    except Exception as exc:  # noqa: BLE001
        err = getattr(exc, "response", {}).get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"the call was expected to be REFUSED but it succeeded, returning {result!r}")


def _delete_role_best_effort(ctx, role_name: str) -> None:
    iam = ctx.client("iam")
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _safe(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
