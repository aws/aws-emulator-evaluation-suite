"""create-endpoint-desired-inference-units-below-minimum-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-endpoint-desired-inference-units-below-minimum-rejected"
GROUP = "overly-permissive"
SERVICES = ["comprehend"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateEndpoint with DesiredInferenceUnits=0 (validation off in the client, so the service judges it)
    fails with ValidationException and its exact message and creates no endpoint; a valid count reaches
    the later InvalidRequestException for a missing ModelArn or FlywheelArn instead."""
    from botocore.config import Config

    comprehend = ctx.client("comprehend")
    endpoint_name = ctx.unique_name("sim2real-ep-")[:38].rstrip("-")

    # A validation-disabled client for the same target, so the request reaches the service
    # instead of being blocked locally by boto3.
    novalidate_comprehend = ctx.client("comprehend", config=Config(parameter_validation=False))

    code, message = _error(
        lambda: novalidate_comprehend.create_endpoint(
            EndpointName=endpoint_name, DesiredInferenceUnits=0
        )
    )
    assert code == "ValidationException", (
        f"expected ValidationException for DesiredInferenceUnits=0, got {code!r}"
    )
    expected = (
        "1 validation error detected: Value at 'desiredInferenceUnits' failed to satisfy "
        "constraint: Member must have value greater than or equal to 1"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: no endpoint was created under this name.
    listed = comprehend.list_endpoints()["EndpointPropertiesList"]
    assert all(endpoint_name not in ep["EndpointArn"] for ep in listed), (
        f"expected no endpoint named {endpoint_name!r} after the rejected CreateEndpoint, "
        f"found it among {listed!r}"
    )

    # Differential positive control: with a valid inference-unit count, the SAME field no
    # longer causes a ValidationException -- the call instead fails later, on the unrelated
    # business rule that CreateEndpoint requires a ModelArn or a FlywheelArn.
    other_code, other_message = _error(
        lambda: comprehend.create_endpoint(
            EndpointName=endpoint_name + "-b", DesiredInferenceUnits=1
        )
    )
    assert other_code == "InvalidRequestException", (
        f"expected InvalidRequestException (missing ModelArn/FlywheelArn) once "
        f"DesiredInferenceUnits is valid, got {other_code!r}"
    )
    expected = "Invalid resource ARN: null"
    assert other_message == expected, f"expected message {expected!r}, got {other_message!r}"

    # Effect absent: the differential-control call was rejected too, so it must not have
    # created an endpoint either.
    other_name = endpoint_name + "-b"
    listed_after = comprehend.list_endpoints()["EndpointPropertiesList"]
    assert all(other_name not in ep["EndpointArn"] for ep in listed_after), (
        f"expected no endpoint named {other_name!r} after the rejected CreateEndpoint, "
        f"found it among {listed_after!r}"
    )


def _error(fn):
    """Call fn(), which must fail; return its botocore error (code, message). An unexpected
    SUCCESS raises, so a target that accepts what AWS refuses is never read as a mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        error = exc.response["Error"]
        return error["Code"], error.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
