"""list-requester-gateways-invalid-max-results-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-requester-gateways-invalid-max-results-rejected"
GROUP = "overly-permissive"
SERVICES = ["rtbfabric"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListRequesterGateways refuses maxResults 0 and 11, outside 1-10, with ValidationException
    from the service (the 0 call skips botocore's client-side check) and accepts an in-range value.
    """
    from botocore.config import Config

    rtb = ctx.client("rtbfabric")
    rtb_unvalidated = ctx.client("rtbfabric", config=Config(parameter_validation=False))

    # Break exactly one thing: maxResults above the documented upper bound of 10.
    over = _client_error(lambda: rtb.list_requester_gateways(maxResults=11))
    assert over["Code"] == "ValidationException", f"expected ValidationException, got {over['Code']}"
    over_message = (
        "1 validation error detected: Value at 'maxResults' failed to satisfy constraint: "
        "Member must have value less than or equal to 10"
    )
    assert over["Message"] == over_message, f"expected {over_message!r}, got {over['Message']!r}"

    # Break exactly one thing: maxResults below the documented lower bound of 1. Validation is
    # disabled on this client so the request actually reaches the server instead of being turned
    # away by botocore's own local model check.
    under = _client_error(lambda: rtb_unvalidated.list_requester_gateways(maxResults=0))
    assert under["Code"] == "ValidationException", f"expected ValidationException, got {under['Code']}"
    under_message = (
        "1 validation error detected: Value at 'maxResults' failed to satisfy constraint: "
        "Member must have value greater than or equal to 1"
    )
    assert under["Message"] == under_message, f"expected {under_message!r}, got {under['Message']!r}"

    # Positive control in the same file: an in-range value must succeed regardless of account contents.
    resp = rtb.list_requester_gateways(maxResults=5)
    assert "gatewayIds" in resp, f"expected a gatewayIds key in the response, got {resp!r}"


def _client_error(fn):
    """Call fn(); return its botocore error (Code and Message). An unexpected SUCCESS raises,
    because a target accepting a call real AWS refuses must fail loudly, not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
