"""get-campaign-state-batch-too-many-ids-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-campaign-state-batch-too-many-ids-rejected"
GROUP = "overly-permissive"
SERVICES = ["connectcampaigns"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetCampaignStateBatch with 500 well-formed nonexistent campaignIds returns all 500 as failedRequests
    and none successful, while 501 ids fail with ValidationException naming the 500-item constraint."""
    campaigns = ctx.client("connectcampaigns")

    at_limit_ids = [ctx.unique_name("nonexistent-campaign-") for _ in range(500)]
    resp = campaigns.get_campaign_state_batch(campaignIds=at_limit_ids)
    assert resp["successfulRequests"] == [], resp
    assert len(resp["failedRequests"]) == 500, (
        f"expected 500 failedRequests at the documented-wrong-but-real limit, "
        f"got {len(resp['failedRequests'])}"
    )

    over_limit_ids = at_limit_ids + [ctx.unique_name("nonexistent-campaign-over-limit-")]
    code, message = _error_code_and_message(
        lambda: campaigns.get_campaign_state_batch(campaignIds=over_limit_ids)
    )
    assert code == "ValidationException", f"expected ValidationException, got {code}"
    expected_message = (
        f"1 validation error detected: Value '[{', '.join(over_limit_ids)}]' at 'campaignIds' "
        "failed to satisfy constraint: Member must have length less than or equal to 500"
    )
    assert message == expected_message, f"unexpected message: {message[-200:]!r}"


def _error_code_and_message(fn):
    from botocore.exceptions import ClientError

    try:
        resp = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected a validation error, but the call succeeded: {resp}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
