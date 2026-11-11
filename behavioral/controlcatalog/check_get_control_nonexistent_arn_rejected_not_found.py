"""get-control-nonexistent-arn-rejected-not-found."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-control-nonexistent-arn-rejected-not-found"
GROUP = "overly-permissive"
SERVICES = ["controlcatalog"]

_NOT_FOUND_MESSAGE = "AWS Control Tower cannot find a control with the ControlArn value that you provided."


@tags("axis:rejection", "cap:c5", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetControl rejects a well-formed ControlArn that does not correspond to any real control
    with ResourceNotFoundException (a distinct boundary from the pattern/length ValidationException
    case), while a real control ARN still succeeds (in-file positive control)."""
    cc = ctx.client("controlcatalog")

    valid_arn = cc.list_controls(MaxResults=1)["Controls"][0]["Arn"]
    ok = cc.get_control(ControlArn=valid_arn)
    assert ok["Arn"] == valid_arn, f"expected positive control to resolve {valid_arn!r}, got {ok!r}"

    # Matches the ControlArn pattern (arn:aws:controlcatalog:::control/<id>) but no such
    # control id has ever been issued.
    bogus_arn = "arn:aws:controlcatalog:::control/nonexistent0000000000000000000000"
    code, message = _error_code(lambda: cc.get_control(ControlArn=bogus_arn))
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for nonexistent {bogus_arn!r}, got {code!r}"
    )
    assert message == _NOT_FOUND_MESSAGE, f"expected {_NOT_FOUND_MESSAGE!r}, got {message!r}"


def _error_code(fn):
    """Call fn(); return its botocore error code. An unexpected SUCCESS raises, because an emulator
    ACCEPTING an id real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
