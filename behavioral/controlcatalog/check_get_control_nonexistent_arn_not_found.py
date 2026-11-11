"""get-control-nonexistent-arn-not-found."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-control-nonexistent-arn-not-found"
GROUP = "errors"
SERVICES = ["controlcatalog"]

_NOT_FOUND_MESSAGE = "AWS Control Tower cannot find a control with the ControlArn value that you provided."


@tags("axis:rejection", "cap:c5", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetControl on a well-formed but nonexistent control ARN returns ResourceNotFoundException."""
    cc = ctx.client("controlcatalog")
    bogus_arn = f"arn:aws:controlcatalog:::control/{ctx.unique_name('sim2real-nf-')}"

    code, message = _error_code(lambda: cc.get_control(ControlArn=bogus_arn))
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for a nonexistent ControlArn, got {code!r}"
    )
    assert message == _NOT_FOUND_MESSAGE, f"expected {_NOT_FOUND_MESSAGE!r}, got {message!r}"

    # positive control: a real control ARN still resolves successfully
    real_arn = cc.list_controls(MaxResults=1)["Controls"][0]["Arn"]
    detail = cc.get_control(ControlArn=real_arn)
    assert detail["Arn"] == real_arn, (
        f"expected GetControl to echo the requested ControlArn {real_arn!r}, got {detail['Arn']!r}"
    )


def _error_code(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(
        f"expected GetControl to reject the nonexistent ControlArn, but it SUCCEEDED and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
