"""validate-resource-policy."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

def _error(fn):
    """Call fn(); return the botocore error (code, message) if a ClientError was raised. An
    unexpected SUCCESS raises instead of returning a falsy sentinel."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")

def _force_delete(sm, secret_id):
    try:
        sm.delete_secret(SecretId=secret_id, ForceDeleteWithoutRecovery=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise

def _create_secret(sm, ctx, name=None, secret_string="initial-value", **kwargs):
    """Create a secret, register its force-delete teardown, and return the raw response."""
    if name is None:
        name = ctx.unique_name("sim2real-behav-" + "secret-")
    params = {"Name": name, "Tags": [{"Key": "sim2real", "Value": CHECK}]}
    if secret_string is not None:
        params["SecretString"] = secret_string
    params.update(kwargs)
    resp = sm.create_secret(**params)
    ctx.on_cleanup(lambda: _force_delete(sm, name))
    return resp

def _self_principal_policy(arn, action="secretsmanager:GetSecretValue"):
    """A minimal, well-formed resource policy naming this account (derived from the
    secret ARN) as principal. Secrets Manager validates that the principal resolves,
    so this real account is accepted where a placeholder would be rejected."""
    account = arn.split(":")[4]
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": f"arn:aws:iam::{account}:root"},
                    "Action": action,
                    "Resource": "*",
                }
            ],
        }
    )

CHECK = "validate-resource-policy"
GROUP = 'error-semantics'
SERVICES = ['secretsmanager']

@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ValidateResourcePolicy passes a well-formed self-principal policy and rejects
    both an unresolvable principal and malformed JSON."""
    sm = ctx.client("secretsmanager")
    name = ctx.unique_name("sim2real-behav-secret-")
    created = _create_secret(sm, ctx, name=name, secret_string="value")

    good_policy = _self_principal_policy(created["ARN"])
    good_result = sm.validate_resource_policy(
        SecretId=name, ResourcePolicy=good_policy
    )
    assert good_result.get("PolicyValidationPassed") is True, (
        "a well-formed self-principal policy must validate; got "
        f"PolicyValidationPassed={good_result.get('PolicyValidationPassed')!r} "
        f"errors={good_result.get('ValidationErrors')}"
    )

    # A syntactically valid policy naming a principal that cannot exist must be rejected.
    bogus_principal = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": "arn:aws:iam::111122223333:root"},
                    "Action": "secretsmanager:GetSecretValue",
                    "Resource": "*",
                }
            ],
        }
    )
    bogus_code, bogus_message = _error(
        lambda: sm.validate_resource_policy(
            SecretId=name, ResourcePolicy=bogus_principal
        )
    )
    assert bogus_code == "MalformedPolicyDocumentException", (
        f"an unresolvable principal must be rejected, got {bogus_code}"
    )
    assert bogus_message == "This resource policy contains an unsupported principal.", (
        f"unexpected refusal message for an unresolvable principal: {bogus_message!r}"
    )

    code, message = _error(
        lambda: sm.validate_resource_policy(
            SecretId=name, ResourcePolicy="{ not valid"
        )
    )
    assert code == "MalformedPolicyDocumentException", (
        f"malformed JSON policy must be rejected, got {code}"
    )
    assert message == "This resource policy contains a syntax error.", (
        f"unexpected refusal message for malformed JSON: {message!r}"
    )

    # Neither throwing negative left the validator itself in a broken state: the identical
    # good-policy call must still pass, using the same SecretId as the positive control.
    again = sm.validate_resource_policy(SecretId=name, ResourcePolicy=good_policy)
    assert again.get("PolicyValidationPassed") is True, (
        "the validator must still accept a well-formed policy after two rejections; got "
        f"PolicyValidationPassed={again.get('PolicyValidationPassed')!r} "
        f"errors={again.get('ValidationErrors')}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
