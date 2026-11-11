"""get-control-malformed-arn-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-control-malformed-arn-rejected"
GROUP = "overly-permissive"
SERVICES = ["controlcatalog"]

_ARN_PATTERN_MESSAGE = (
    "1 validation error detected: Value at 'controlArn' failed to satisfy constraint: Member must "
    "satisfy regular expression pattern: "
    "arn:(aws(?:[-a-z]*)?):(controlcatalog|controltower):[a-zA-Z0-9-]*::control/[0-9a-zA-Z_\\-]+"
)


@tags("axis:rejection", "cap:c5", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetControl rejects a ControlArn that doesn't match the required ARN pattern with
    ValidationException, while a real control ARN still succeeds (in-file positive control)."""
    cc = ctx.client("controlcatalog")

    valid_arn = cc.list_controls(MaxResults=1)["Controls"][0]["Arn"]
    ok = cc.get_control(ControlArn=valid_arn)
    assert ok["Arn"] == valid_arn, f"positive control failed: expected Arn {valid_arn!r}, got {ok.get('Arn')!r}"

    code, message = _error_code(lambda: cc.get_control(ControlArn="not-a-valid-control-arn-but-long-enough-1234567890"))
    assert code == "ValidationException", f"expected ValidationException for a malformed ControlArn, got {code!r}"
    assert message == _ARN_PATTERN_MESSAGE, f"expected {_ARN_PATTERN_MESSAGE!r}, got {message!r}"


def _error_code(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError for a malformed ControlArn, but the call succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
