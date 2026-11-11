"""get-control-nonexistent-wellformed-arn-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-control-nonexistent-wellformed-arn-not-found"
GROUP = "error-semantics"
SERVICES = ["controlcatalog"]

_NOT_FOUND_MESSAGE = "AWS Control Tower cannot find a control with the ControlArn value that you provided."


def _error_code(fn):
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError but the call succeeded with {result!r}")


@tags("axis:rejection", "cap:c5", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetControl on a well-formed but nonexistent control ARN returns ResourceNotFoundException."""
    cc = ctx.client("controlcatalog")

    # Well-formed per the ControlArn pattern (arn:aws:controlcatalog:::control/<id>) but not a
    # real control id, so it must fail existence lookup rather than input validation.
    bogus_arn = "arn:aws:controlcatalog:::control/SIM2REAL0000NONEXISTENTCTRL00001"
    assert 34 <= len(bogus_arn) <= 2048, (
        f"fixture ARN {bogus_arn!r} (len={len(bogus_arn)}) must satisfy the modelled "
        "ControlArn length bounds [34, 2048] to exercise not-found rather than validation"
    )

    code, message = _error_code(lambda: cc.get_control(ControlArn=bogus_arn))
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for well-formed but nonexistent ControlArn, got {code!r}"
    )
    assert message == _NOT_FOUND_MESSAGE, f"expected {_NOT_FOUND_MESSAGE!r}, got {message!r}"

    # Positive control: a real control ARN (dynamically discovered) must still resolve.
    real_arn = cc.list_controls(MaxResults=1)["Controls"][0]["Arn"]
    detail = cc.get_control(ControlArn=real_arn)
    assert detail["Arn"] == real_arn, (
        f"expected GetControl(ControlArn={real_arn!r}) to echo the same Arn, got {detail.get('Arn')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
