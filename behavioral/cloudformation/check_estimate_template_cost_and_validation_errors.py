"""estimate-template-cost-and-validation-errors."""
from __future__ import annotations

import json
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "estimate-template-cost-and-validation-errors"
GROUP = 'template_validation'
SERVICES = ['cloudformation']


def _expect_error(fn):
    """Call fn(); return the raised ClientError. Raise if fn() succeeds unexpectedly."""
    try:
        result = fn()
    except ClientError as exc:
        return exc
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")

def _invalid_template():
    # Not valid CloudFormation: a Resources entry missing the required "Type"
    # member. Triggers a precise template-validation error.
    return json.dumps({"Resources": {"Bad": {"Properties": {}}}})


def _valid_template():
    return json.dumps({"Resources": {"Bucket": {"Type": "AWS::S3::Bucket"}}})


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A malformed template gets the same exact ValidationError from ValidateTemplate and
    EstimateTemplateCost, while a well-formed template succeeds on both (positive control)."""
    cf = ctx.client("cloudformation")
    good_template = _valid_template()
    bad_template = _invalid_template()

    good_validate = cf.validate_template(TemplateBody=good_template)
    assert isinstance(good_validate.get("Parameters"), list), (
        f"ValidateTemplate on a well-formed template returned no Parameters list: {good_validate!r}"
    )

    good_estimate = cf.estimate_template_cost(TemplateBody=good_template)
    assert good_estimate.get("Url", "").startswith("http"), (
        f"EstimateTemplateCost on a well-formed template returned no cost-calculator URL: "
        f"{good_estimate!r}"
    )

    expected_message = (
        "Template format error: [/Resources/Bad] Every Resources object must contain a Type member."
    )
    err1 = _expect_error(lambda: cf.validate_template(TemplateBody=bad_template)).response["Error"]
    assert err1["Code"] == "ValidationError", f"expected ValidationError, got {err1['Code']}"
    assert err1.get("Message") == expected_message, (
        f"ValidateTemplate: expected message {expected_message!r}, got {err1.get('Message')!r}"
    )

    err2 = _expect_error(lambda: cf.estimate_template_cost(TemplateBody=bad_template)).response["Error"]
    assert err2["Code"] == "ValidationError", f"expected ValidationError, got {err2['Code']}"
    assert err2.get("Message") == expected_message, (
        f"EstimateTemplateCost: expected message {expected_message!r}, got {err2.get('Message')!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
