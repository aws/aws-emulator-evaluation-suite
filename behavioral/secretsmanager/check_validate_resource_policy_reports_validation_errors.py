"""validate-resource-policy-reports-validation-errors."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

# ValidateResourcePolicy accepts a call with no SecretId, so this check creates no resource
# and needs no teardown.


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError raised; a success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


CHECK = "validate-resource-policy-reports-validation-errors"
GROUP = 'overly-permissive'
SERVICES = ['secretsmanager']


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ValidateResourcePolicy returns PolicyValidationPassed=False with a BlockPublicPolicyCheck
    error for a Principal:"*" policy, while non-policies and unresolvable principals throw instead.
    """
    sm = ctx.client("secretsmanager")

    # ValidateResourcePolicy resolves the named principal, so a placeholder account would be
    # refused as malformed; the baseline names the caller's own account root.
    account = ctx.client("sts").get_caller_identity()["Account"]
    scoped = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "sim2realScopedRead",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account}:root"},
                "Action": "secretsmanager:GetSecretValue",
                "Resource": "*",
            }
        ],
    }
    ok = sm.validate_resource_policy(ResourcePolicy=json.dumps(scoped))
    assert ok["PolicyValidationPassed"] is True, (
        "a policy naming a single account principal must validate; got "
        f"PolicyValidationPassed={ok.get('PolicyValidationPassed')!r} "
        f"errors={ok.get('ValidationErrors')}"
    )
    assert ok.get("ValidationErrors", []) == [], (
        f"a passing validation must report no errors, got {ok.get('ValidationErrors')}"
    )

    # A syntactically valid policy that grants everyone.
    public = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "sim2realPublicRead",
                "Effect": "Allow",
                "Principal": "*",
                "Action": "secretsmanager:GetSecretValue",
                "Resource": "*",
            }
        ],
    }
    bad = sm.validate_resource_policy(ResourcePolicy=json.dumps(public))
    assert bad["PolicyValidationPassed"] is False, (
        "a policy with Principal:'*' must NOT pass validation; returning True here is "
        "the exact failure that lets a caller publish a world-readable secret policy"
    )
    errors = bad.get("ValidationErrors") or []
    assert errors, (
        "PolicyValidationPassed=False must be accompanied by at least one "
        f"ValidationErrors entry explaining why; response was {sorted(bad)}"
    )
    for entry in errors:
        assert entry.get("CheckName"), (
            f"each ValidationErrors entry must name the failing check, got {entry}"
        )
        assert entry.get("ErrorMessage"), (
            f"each ValidationErrors entry must carry a human-readable message, got {entry}"
        )
    # Callers branch on CheckName to tell "too public" apart from other validation findings.
    assert "BlockPublicPolicyCheck" in {e.get("CheckName") for e in errors}, (
        f"a Principal:'*' policy must be reported by BlockPublicPolicyCheck, got {errors}"
    )
    public_reasons = [
        e.get("ErrorMessage") for e in errors if e.get("CheckName") == "BlockPublicPolicyCheck"
    ]
    assert public_reasons == [
        "You can not attach a resource policy that grants Public access to your secret."
    ], f"unexpected BlockPublicPolicyCheck ErrorMessage: {public_reasons!r}"

    # Second channel, kept distinct: valid JSON that is not a policy must THROW,
    # not come back as a validation error.
    code, message = _error(
        lambda: sm.validate_resource_policy(
            ResourcePolicy=json.dumps({"Version": "2012-10-17"})
        )
    )
    assert code == "MalformedPolicyDocumentException", (
        "valid JSON with no Statement element is not a policy and belongs on the "
        f"throwing channel, not in ValidationErrors; got {code}"
    )
    assert message == "This resource policy contains a syntax error.", (
        f"unexpected refusal message for a document with no Statement: {message!r}"
    )

    # Third channel, also throwing: the documentation-reserved 111122223333 account does not
    # resolve, so the policy is refused rather than validated.
    unresolvable = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "sim2realUnresolvablePrincipal",
                "Effect": "Allow",
                "Principal": {"AWS": "arn:aws:iam::111122223333:root"},
                "Action": "secretsmanager:GetSecretValue",
                "Resource": "*",
            }
        ],
    }
    code_principal, message_principal = _error(
        lambda: sm.validate_resource_policy(ResourcePolicy=json.dumps(unresolvable))
    )
    assert code_principal == "MalformedPolicyDocumentException", (
        "a principal naming an account that does not exist must be refused on the throwing "
        f"channel, not validated; got {code_principal}"
    )
    assert message_principal == "This resource policy contains an unsupported principal.", (
        f"unexpected refusal message for an unresolvable principal: {message_principal!r}"
    )

    # Control: the validator is still usable after the refusal.
    again = sm.validate_resource_policy(ResourcePolicy=json.dumps(scoped))
    assert again["PolicyValidationPassed"] is True, (
        "validator must still accept the same scoped policy after the preceding refusals; got "
        f"PolicyValidationPassed={again.get('PolicyValidationPassed')!r} errors={again.get('ValidationErrors')}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
