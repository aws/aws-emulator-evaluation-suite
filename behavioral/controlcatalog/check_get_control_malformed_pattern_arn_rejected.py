"""get-control-malformed-pattern-arn-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-control-malformed-pattern-arn-rejected"
GROUP = "overly-permissive"
SERVICES = ["controlcatalog"]

_ARN_PATTERN_MESSAGE = (
    "1 validation error detected: Value at 'controlArn' failed to satisfy constraint: Member must "
    "satisfy regular expression pattern: "
    "arn:(aws(?:[-a-z]*)?):(controlcatalog|controltower):[a-zA-Z0-9-]*::control/[0-9a-zA-Z_\\-]+"
)


@tags("axis:rejection", "cap:c5", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetControl rejects an ARN of valid length whose service segment is neither controlcatalog nor controltower."""
    cc = ctx.client("controlcatalog")
    bad_arn = "arn:aws:s3:::control/" + "a" * 20  # valid length, wrong service segment

    code, message = _error_code(lambda: cc.get_control(ControlArn=bad_arn))
    assert code == "ValidationException", f"expected ValidationException for wrong-service ARN, got {code!r}"
    assert message == _ARN_PATTERN_MESSAGE, f"expected {_ARN_PATTERN_MESSAGE!r}, got {message!r}"

    # positive control: a real, well-formed control ARN still succeeds
    real_arn = cc.list_controls(MaxResults=1)["Controls"][0]["Arn"]
    detail = cc.get_control(ControlArn=real_arn)
    assert detail["Arn"] == real_arn, f"expected GetControl to echo {real_arn!r}, got {detail.get('Arn')!r}"


def _error_code(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
