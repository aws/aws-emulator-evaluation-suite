"""delete-endpoint-invalid-endpoint-id-format-validation-error."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "delete-endpoint-invalid-endpoint-id-format-validation-error"
GROUP = "validation"
SERVICES = ["s3outposts"]

VALIDATION_PREFIX = "1 validation error detected: Value '{}' at '{}' failed to satisfy constraint: "
ENDPOINT_ID_PATTERN = r"^[a-zA-Z0-9]{19}$"
ACCESS_DENIED = "Access Denied"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteEndpoint rejects a malformed EndpointId with ValidationException -- distinct from
    the ResourceNotFoundException a well-formed but unknown EndpointId gets."""
    s3o = ctx.client("s3outposts")
    outpost_id = "op-" + "0" * 17

    bad_code, bad_message = _error(
        lambda: s3o.delete_endpoint(EndpointId="short-id", OutpostId=outpost_id)
    )
    assert bad_code == "ValidationException", f"got={bad_code!r}"
    expected = VALIDATION_PREFIX.format("short-id", "endpointId") + (
        "Member must satisfy regular expression pattern: " + ENDPOINT_ID_PATTERN
    )
    assert bad_message == expected, f"message={bad_message!r}"

    # Positive control: a well-formed (19 alphanumeric chars) but unknown EndpointId against
    # the same OutpostId must fail differently, isolating the pattern as the cause above.
    control_code, control_message = _error(
        lambda: s3o.delete_endpoint(EndpointId="A1B2C3D4E5F6G7H8I9J", OutpostId=outpost_id)
    )
    assert control_code == "ResourceNotFoundException", f"got={control_code!r}"
    assert control_message == ACCESS_DENIED, f"message={control_message!r}"


def _error(fn):
    """Call fn(); return its (code, message). An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
