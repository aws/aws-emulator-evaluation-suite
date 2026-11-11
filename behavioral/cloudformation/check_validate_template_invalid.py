"""validate-template-invalid."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "validate-template-invalid"
GROUP = 'template_validation'
SERVICES = ['cloudformation']

_VALID_TEMPLATE = (
    '{"AWSTemplateFormatVersion": "2010-09-09", '
    '"Resources": {"Handle": {"Type": "AWS::CloudFormation::WaitConditionHandle"}}}'
)


def _error(fn):
    """Call fn(); return botocore (Error.Code, Error.Message) if a ClientError is raised. An
    unexpected SUCCESS raises, because a target that accepts input real AWS refuses is the strongest
    signal available."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected ValidateTemplate to reject this call, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ValidateTemplate on invalid JSON raises ValidationError.

    Positive control first: the same call, on a well-formed template, must succeed -- otherwise
    a target that refuses every ValidateTemplate call would pass this check for the wrong reason.
    """
    cf = ctx.client("cloudformation")

    control = cf.validate_template(TemplateBody=_VALID_TEMPLATE)
    assert isinstance(control.get("Parameters"), list), (
        f"positive control: a well-formed template must validate and report Parameters, got {control!r}"
    )

    error = _error(lambda: cf.validate_template(TemplateBody="this is not valid json or yaml {"))
    assert error == ("ValidationError", "Template format error: unsupported structure."), (
        f"Expected ValidationError 'Template format error: unsupported structure.', got {error!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
