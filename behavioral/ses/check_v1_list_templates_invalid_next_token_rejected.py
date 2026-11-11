"""v1-list-templates-invalid-next-token-rejected."""
from __future__ import annotations

from typing import Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "v1-list-templates-invalid-next-token-rejected"
GROUP = "error-semantics"
SERVICES = ["ses"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListTemplates with a malformed NextToken is rejected with InvalidParameterValue
    naming the bad token, while the same call without a token still succeeds (positive
    control)."""
    ses = ctx.client("ses")

    err = _error(lambda: ses.list_templates(NextToken="not-a-real-pagination-token"))
    expected = ("InvalidParameterValue", "Invalid PageToken <not-a-real-pagination-token>.")
    assert err == expected, f"expected {expected!r}, got {err!r}"

    # positive control: an unpaginated call still succeeds
    resp = ses.list_templates()
    assert "TemplatesMetadata" in resp, (
        f"expected TemplatesMetadata in positive-control response, got keys={list(resp)!r}"
    )


def _error(fn: Callable[[], object]) -> tuple[str, str]:
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
