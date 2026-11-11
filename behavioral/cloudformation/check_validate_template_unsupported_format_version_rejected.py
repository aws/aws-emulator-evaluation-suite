"""validate-template-unsupported-format-version-rejected."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "validate-template-unsupported-format-version-rejected"
GROUP = "negative-classes"
SERVICES = ["cloudformation"]


def _template(version: str) -> str:
    return json.dumps(
        {
            "AWSTemplateFormatVersion": version,
            "Resources": {"Q": {"Type": "AWS::SQS::Queue"}},
        }
    )


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ValidateTemplate rejects an AWSTemplateFormatVersion value other than the one
    supported value, with the exact unsupported-value message, while the same template
    with the supported version string validates cleanly."""
    cf = ctx.client("cloudformation")

    code, message = _error(
        lambda: cf.validate_template(TemplateBody=_template("2010-09-08"))
    )
    assert code == "ValidationError", f"expected ValidationError, got {code!r}: {message!r}"
    expected = (
        "Template format error: 2010-09-08 is not a supported value forAWSTemplateFormatVersion."
    )
    assert message == expected, f"expected {expected!r}, got {message!r}"

    # Positive control: the same template with the one supported version validates cleanly.
    ok = cf.validate_template(TemplateBody=_template("2010-09-09"))
    assert ok["Parameters"] == [], f"the supported-version control must validate cleanly, got {ok!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
