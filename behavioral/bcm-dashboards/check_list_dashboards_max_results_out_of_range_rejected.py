"""list-dashboards-max-results-out-of-range-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-dashboards-max-results-out-of-range-rejected"
GROUP = "overly-permissive"
SERVICES = ["bcm-dashboards"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListDashboards rejects a maxResults value above the documented [1,100] range
    with ValidationException, while a value inside the range succeeds in the same file."""
    bcm = ctx.client("bcm-dashboards")

    code, message = _client_error(lambda: bcm.list_dashboards(maxResults=101))
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    assert message == (
        "1 validation error detected: Value '101' at 'maxResults' failed to satisfy constraint: "
        "Member must have value less than or equal to 100"
    ), message

    # positive control: a value inside the documented range succeeds
    resp = bcm.list_dashboards(maxResults=100)
    assert "dashboards" in resp, f"expected a dashboards key in the response, got {resp!r}"


def _client_error(fn) -> tuple[str, str]:
    """Call fn(); return its ClientError (code, message). An unexpected SUCCESS raises, so an
    emulator accepting what real AWS refuses fails loudly instead of as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
