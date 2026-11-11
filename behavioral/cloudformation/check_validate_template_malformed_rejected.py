"""validate-template-malformed-rejected."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "validate-template-malformed-rejected"
GROUP = 'overly-permissive'
SERVICES = ['cloudformation']

_GOOD_TEMPLATE = json.dumps({
    "AWSTemplateFormatVersion": "2010-09-09",
    "Resources": {"Topic": {"Type": "AWS::SNS::Topic"}},
})


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ValidateTemplate rejects a template with no Resources section with ValidationError and the
    exact "At least one Resources member must be defined." message, while the same template with a
    Resources section is accepted (positive control)."""
    cfn = ctx.client("cloudformation")

    good = cfn.validate_template(TemplateBody=_GOOD_TEMPLATE)
    assert good is not None, "positive control: ValidateTemplate rejected a well-formed template"

    bad = json.dumps({"AWSTemplateFormatVersion": "2010-09-09", "Description": "no resources"})
    error = _validation_error(lambda: cfn.validate_template(TemplateBody=bad))
    assert error.get("Code") == "ValidationError", (
        f"expected Code=ValidationError for a template with no Resources section, got {error!r}"
    )
    assert error.get("Message") == "Template format error: At least one Resources member must be defined.", (
        f"expected the error message to name the missing Resources section, got {error!r}"
    )


def _validation_error(fn):
    """Call fn(); return the botocore Error dict of a raised ClientError. An unexpected SUCCESS
    raises, so an over-permissive target is reported as accepting, not as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(
        f"expected ValidateTemplate to reject the template with no Resources section, but it "
        f"SUCCEEDED and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
