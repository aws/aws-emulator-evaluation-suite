"""list-datastores-maxresults-out-of-range-rejected."""
from __future__ import annotations

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-datastores-maxresults-out-of-range-rejected"
GROUP = "overly-permissive"
SERVICES = ["medical-imaging"]


def _client_error(fn) -> tuple[str, str]:
    """Call fn(); return its botocore (error code, error message). An unexpected SUCCESS raises,
    because an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListDatastores with maxResults below and above the documented 1-50 range, sent with client-side
    validation off, fails ValidationException with the exact message from the service, while an in-range
    value returns datastoreSummaries."""
    # maxResults carries a min:1/max:50 range constraint in the model, so a validating client
    # raises ParamValidationError locally and the out-of-range value never reaches the service.
    mi = ctx.client("medical-imaging", config=Config(parameter_validation=False))

    code, message = _client_error(lambda: mi.list_datastores(maxResults=51))
    assert code == "ValidationException", (
        f"expected ValidationException for maxResults=51 (above the documented max of 50), got {code!r}"
    )
    expected_message = (
        "1 validation error detected: Value '51' at 'maxResults' failed to satisfy constraint: "
        "Member must have value less than or equal to 50"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    code, message = _client_error(lambda: mi.list_datastores(maxResults=0))
    assert code == "ValidationException", (
        f"expected ValidationException for maxResults=0 (below the documented min of 1), got {code!r}"
    )
    expected_message = (
        "1 validation error detected: Value '0' at 'maxResults' failed to satisfy constraint: "
        "Member must have value greater than or equal to 1"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Positive control: an in-range maxResults still succeeds.
    resp = mi.list_datastores(maxResults=10)
    assert "datastoreSummaries" in resp, f"expected datastoreSummaries in response, got {resp!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
