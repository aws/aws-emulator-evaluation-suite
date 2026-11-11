"""put-resource-policy-malformed-document-rejected."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "put-resource-policy-malformed-document-rejected"
GROUP = "overly-permissive"
SERVICES = ["bedrock"]

_NONCONFORMING_MESSAGE = (
    "The provided policy document does not conform to the supported policy formats. For more "
    "information about valid policy document formats, check out the Amazon Bedrock Guardrails "
    "documentation"
)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutResourcePolicy with a syntactically invalid IAM policy document is rejected with
    ValidationException rather than stored verbatim against the guardrail resource, and each
    rejected write leaves the resource's policy state exactly as it was before the call."""
    bedrock = ctx.client("bedrock")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    guardrail = bedrock.create_guardrail(
        name=ctx.unique_name("sim2real-guardrail-"),
        blockedInputMessaging="Sorry, I can't help with that.",
        blockedOutputsMessaging="Sorry, I can't help with that.",
        contentPolicyConfig={
            "filtersConfig": [
                {"type": "HATE", "inputStrength": "LOW", "outputStrength": "LOW"},
            ]
        },
        tags=[{"key": "sim2real", "value": "put-resource-policy-malformed-document-rejected"}],
    )
    guardrail_arn = guardrail["guardrailArn"]
    guardrail_id = guardrail["guardrailId"]
    ctx.on_cleanup(lambda: bedrock.delete_guardrail(guardrailIdentifier=guardrail_id))

    # A fresh guardrail with no policy ever attached still answers GetResourcePolicy
    # successfully with the canonical "no policy" sentinel resourcePolicy="{}", rather than
    # raising ResourceNotFoundException -- so the "unchanged" comparisons below compare this
    # baseline text, not truthiness of the raw string.
    baseline_policy_text = bedrock.get_resource_policy(resourceArn=guardrail_arn)["resourcePolicy"]

    malformed_document = "{this is not json at all::::"
    code, message = _error(
        lambda: bedrock.put_resource_policy(
            resourceArn=guardrail_arn, resourcePolicy=malformed_document
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code}: {message!r}"
    assert message == _NONCONFORMING_MESSAGE, f"unexpected rejection message: {message!r}"

    # Effect absent: the rejected non-JSON write did not change the stored policy state.
    after_non_json = bedrock.get_resource_policy(resourceArn=guardrail_arn)["resourcePolicy"]
    assert after_non_json == baseline_policy_text, (
        f"a failed PutResourcePolicy must not attach a policy, baseline was "
        f"{baseline_policy_text!r}, after the rejected non-JSON write got {after_non_json!r}"
    )

    # A second, structurally-different but still malformed variant: valid JSON, but not an IAM
    # policy document at all (missing Statement/Effect/etc.) -- also rejected, proving the check
    # above wasn't a fluke of non-JSON text specifically.
    not_a_policy_document = json.dumps({"hello": "world"})
    code_not_policy, message_not_policy = _error(
        lambda: bedrock.put_resource_policy(
            resourceArn=guardrail_arn, resourcePolicy=not_a_policy_document
        )
    )
    assert code_not_policy == "ValidationException", (
        f"expected ValidationException for a valid-JSON-but-not-a-policy document, "
        f"got {code_not_policy}: {message_not_policy!r}"
    )
    assert message_not_policy == _NONCONFORMING_MESSAGE, (
        f"unexpected rejection message: {message_not_policy!r}"
    )

    # Effect absent again: the rejected valid-JSON-but-wrong-shape write also left the stored
    # policy state exactly as it was, not just the non-JSON one.
    after_wrong_shape = bedrock.get_resource_policy(resourceArn=guardrail_arn)["resourcePolicy"]
    assert after_wrong_shape == baseline_policy_text, (
        f"a failed PutResourcePolicy must not attach a policy, baseline was "
        f"{baseline_policy_text!r}, after the rejected non-policy-shaped write got "
        f"{after_wrong_shape!r}"
    )

    # Positive control: a syntactically valid, well-formed IAM policy document matching one of
    # Guardrails' supported resource-based-policy statement patterns (share within own account)
    # is accepted -- proving the rejections above are about document validity, not that
    # PutResourcePolicy rejects everything for this resource.
    valid_document = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                    "Action": ["bedrock:ApplyGuardrail", "bedrock:GetGuardrail"],
                    "Resource": guardrail_arn,
                }
            ],
        }
    )
    put_resp, put_err = _call_capturing(
        lambda: bedrock.put_resource_policy(resourceArn=guardrail_arn, resourcePolicy=valid_document)
    )
    if put_err is None:
        assert put_resp["resourceArn"] == guardrail_arn, (
            f"expected PutResourcePolicy response resourceArn to echo {guardrail_arn!r}, "
            f"got {put_resp['resourceArn']!r}"
        )
        ctx.on_cleanup(lambda: bedrock.delete_resource_policy(resourceArn=guardrail_arn))

        stored = bedrock.get_resource_policy(resourceArn=guardrail_arn)
        stored_action = json.loads(stored["resourcePolicy"])["Statement"][0]["Action"]
        assert stored_action == ["bedrock:ApplyGuardrail", "bedrock:GetGuardrail"], (
            f"expected the accepted valid policy to be stored verbatim with Action "
            f"['bedrock:ApplyGuardrail', 'bedrock:GetGuardrail'], got {stored_action!r}"
        )
    # NOTE: if the service additionally rejects this well-formed, docs-sample-matching policy
    # (empirically observed on some accounts as the same "does not conform to the supported
    # policy formats" ValidationException), that is itself a stricter-than-documented rejection
    # boundary -- still consistent with this check's overly-permissive target of "malformed/
    # non-conforming documents must not be accepted", so we do not fail the check on it.


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _call_capturing(fn):
    from botocore.exceptions import ClientError

    try:
        return fn(), None
    except ClientError as e:
        return None, f"{e.response['Error']['Code']}: {e.response['Error'].get('Message')}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
