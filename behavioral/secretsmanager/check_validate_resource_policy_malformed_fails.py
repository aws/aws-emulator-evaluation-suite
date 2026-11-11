"""validate-resource-policy-malformed-fails."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

def _error(fn):
    """Call fn(); return the botocore error (code, message). An unexpected SUCCESS raises, so
    a target that accepts what AWS refuses cannot read as a plain code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")

CHECK = "validate-resource-policy-malformed-fails"
GROUP = 'error-semantics'
SERVICES = ['secretsmanager']

@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ValidateResourcePolicy rejects a policy document that isn't valid JSON/IAM grammar --
    with a positive control either side, since without one the rejection is
    indistinguishable from a validator that throws on every call regardless of input."""
    sm = ctx.client("secretsmanager")

    account = ctx.client("sts").get_caller_identity()["Account"]
    well_formed = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "sim2realPositiveControl",
                    "Effect": "Allow",
                    "Principal": {"AWS": f"arn:aws:iam::{account}:root"},
                    "Action": "secretsmanager:GetSecretValue",
                    "Resource": "*",
                }
            ],
        }
    )
    control = sm.validate_resource_policy(ResourcePolicy=well_formed)
    assert control.get("PolicyValidationPassed") is True, (
        "positive control: a well-formed self-principal policy must validate with no "
        f"SecretId, got PolicyValidationPassed={control.get('PolicyValidationPassed')!r} "
        f"errors={control.get('ValidationErrors')}"
    )

    code, message = _error(
        lambda: sm.validate_resource_policy(ResourcePolicy="{not valid json")
    )
    assert code == "MalformedPolicyDocumentException", f"expected MalformedPolicyDocumentException, got {code}"
    assert message == "This resource policy contains a syntax error.", f"unexpected refusal message: {message!r}"

    again = sm.validate_resource_policy(ResourcePolicy=well_formed)
    assert again.get("PolicyValidationPassed") is True, (
        "the validator must remain usable after rejecting malformed input, got "
        f"{again}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
