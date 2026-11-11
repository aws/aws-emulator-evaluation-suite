"""list-campaigns-max-results-out-of-range-rejected."""
from __future__ import annotations

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-campaigns-max-results-out-of-range-rejected"
GROUP = "overly-permissive"
SERVICES = ["connectcampaigns"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListCampaigns with maxResults=0 (validation off in the client, so the service judges it) fails with
    ValidationException and its exact message, while maxResults=1 returns at most one summary."""
    cc = ctx.client("connectcampaigns")

    # positive control: a valid maxResults value is accepted (list may be empty, that's fine)
    result = cc.list_campaigns(maxResults=1)
    assert "campaignSummaryList" in result
    assert len(result["campaignSummaryList"]) <= 1

    raw = ctx.client("connectcampaigns", config=Config(parameter_validation=False))
    code, message = _error(lambda: raw.list_campaigns(maxResults=0))
    assert code == "ValidationException", code
    assert message == (
        "1 validation error detected: Value at 'maxResults' failed to satisfy constraint: "
        "Member must have value greater than or equal to 1"
    ), message


def _error(fn) -> tuple[str, str]:
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError("expected the call to be refused, but it succeeded")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

