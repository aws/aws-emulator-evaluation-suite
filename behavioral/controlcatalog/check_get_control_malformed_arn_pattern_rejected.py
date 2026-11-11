"""get-control-malformed-arn-pattern-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-control-malformed-arn-pattern-rejected"
GROUP = "overly-permissive"
SERVICES = ["controlcatalog"]

_ARN_PATTERN_MESSAGE = (
    "1 validation error detected: Value at 'controlArn' failed to satisfy constraint: Member must "
    "satisfy regular expression pattern: "
    "arn:(aws(?:[-a-z]*)?):(controlcatalog|controltower):[a-zA-Z0-9-]*::control/[0-9a-zA-Z_\\-]+"
)


def _error_code(fn):
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected GetControl to reject the ControlArn, but it SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c5", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetControl rejects a ControlArn that does not match the required controlcatalog/controltower ARN
    pattern (a plain string, or an ARN for a wholly different resource type/service)."""
    cc = ctx.client("controlcatalog")

    # Positive control: a real, well-formed control ARN (dynamically discovered) succeeds,
    # proving the account/credentials are otherwise healthy before the negatives below.
    real_arn = cc.list_controls(MaxResults=1)["Controls"][0]["Arn"]
    detail = cc.get_control(ControlArn=real_arn)
    assert detail["Arn"] == real_arn, f"expected GetControl({real_arn!r}) to echo that ARN, got {detail.get('Arn')!r}"

    code, message = _error_code(
        lambda: cc.get_control(ControlArn="not-a-control-arn-at-all-but-padded-to-be-long-enough")
    )
    assert code == "ValidationException", f"expected ValidationException for a non-ARN ControlArn, got {code!r}"
    assert message == _ARN_PATTERN_MESSAGE, f"expected {_ARN_PATTERN_MESSAGE!r} for a non-ARN ControlArn, got {message!r}"

    code_wrong_service, message_wrong_service = _error_code(
        lambda: cc.get_control(ControlArn="arn:aws:s3:::some-bucket/some-key-that-is-long-enough")
    )
    assert code_wrong_service == "ValidationException", (
        f"expected ValidationException for a wrong-service ControlArn, got {code_wrong_service!r}"
    )
    assert message_wrong_service == _ARN_PATTERN_MESSAGE, (
        f"expected {_ARN_PATTERN_MESSAGE!r} for a wrong-service ControlArn, got {message_wrong_service!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
