"""op-contract-validateTemplate."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "op-contract-validateTemplate"
GROUP = "error-semantics"
SERVICES = ["cloudformation"]

_BUCKET_TEMPLATE = json.dumps({"Resources": {"Bucket": {"Type": "AWS::S3::Bucket"}}})

_IAM_TEMPLATE = json.dumps(
    {
        "Resources": {
            "Role": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {"Service": "lambda.amazonaws.com"},
                                "Action": "sts:AssumeRole",
                            }
                        ],
                    }
                },
            }
        }
    }
)


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ValidateTemplate requires no capabilities for a plain template, reports CAPABILITY_IAM for
    an IAM role template, and rejects a malformed template with an exact ValidationError."""
    cfn = ctx.client("cloudformation")

    plain = cfn.validate_template(TemplateBody=_BUCKET_TEMPLATE)
    plain_caps = plain.get("Capabilities", [])
    assert plain_caps == [], f"expected no required capabilities for a plain S3 template, got {plain_caps!r}"

    with_iam = cfn.validate_template(TemplateBody=_IAM_TEMPLATE)
    iam_caps = with_iam.get("Capabilities", [])
    assert "CAPABILITY_IAM" in iam_caps, f"expected CAPABILITY_IAM for a template with an IAM role, got {iam_caps!r}"

    code, message = _error(
        lambda: cfn.validate_template(TemplateBody="{ this is neither json nor yaml @@@")
    )
    assert code == "ValidationError", f"expected ValidationError for malformed template, got {code}"
    expected = "Template format error: YAML not well-formed. (line 1, column 36)"
    assert message == expected, f"expected ValidateTemplate refusal message {expected!r}, got {message!r}"




def _error(fn):
    """Call fn(); return (Error.Code, Error.Message) of the raised ClientError; raise on success."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this malformed template, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
