"""get-campaign-state-batch-empty-list-rejected."""
from __future__ import annotations

from botocore.config import Config

from behavioral_harness import tags

CHECK = "get-campaign-state-batch-empty-list-rejected"
GROUP = "overly-permissive"
SERVICES = ["connectcampaigns"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetCampaignStateBatch rejects an empty campaignIds list (min length 1) with a
    server-side ValidationException."""
    campaigns = ctx.client("connectcampaigns")

    # Positive control: a non-empty list (even with an id that doesn't exist) is a
    # structurally valid request and does not raise -- it reports the id as failed.
    resp = campaigns.get_campaign_state_batch(
        campaignIds=[ctx.unique_name("nonexistent-campaign-")]
    )
    assert resp["successfulRequests"] == []
    assert len(resp["failedRequests"]) == 1

    # campaignIds carries a min:1 length constraint in the model, so botocore's own
    # client-side parameter validator raises ParamValidationError before the request
    # ever reaches the wire -- an emulator that happily accepted an empty list would
    # still be graded green. Disable client-side validation so the malformed request
    # actually goes on the wire and it is the service's own rejection that gets asserted.
    unvalidated = ctx.client("connectcampaigns", config=Config(parameter_validation=False))
    code, message = _error_code_and_message(
        lambda: unvalidated.get_campaign_state_batch(campaignIds=[])
    )
    assert code == "ValidationException", (
        f"expected a server-side ValidationException for an empty campaignIds list, got {code!r}"
    )
    assert message == (
        "1 validation error detected: Value '[]' at 'campaignIds' failed to satisfy constraint: "
        "Member must have length greater than or equal to 1"
    ), message


def _error_code_and_message(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
