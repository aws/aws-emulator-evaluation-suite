"""get-campaign-state-batch-invalid-id-pattern-rejected."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-campaign-state-batch-invalid-id-pattern-rejected"
GROUP = "error-semantics"
SERVICES = ["connectcampaignsv2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetCampaignStateBatch rejects a campaignId outside the [-:/a-zA-Z0-9]+ pattern with the exact
    ValidationException, while a well-formed unknown id lands in failedRequests: a malformed id fails
    the whole call, an unknown one fails per item."""
    campaigns = ctx.client("connectcampaignsv2")

    well_formed_id = str(uuid.uuid4())
    control = campaigns.get_campaign_state_batch(campaignIds=[well_formed_id])
    control_failed_ids = [r["campaignId"] for r in control.get("failedRequests", [])]
    assert well_formed_id in control_failed_ids, (
        f"expected {well_formed_id} in failedRequests as a per-item unknown-id failure, "
        f"got {control!r}"
    )

    bad_id = "not a valid id!"

    def _get_batch():
        return campaigns.get_campaign_state_batch(campaignIds=[bad_id])

    err = _error(_get_batch)
    assert err["Code"] == "ValidationException", f"expected ValidationException, got {err['Code']}"
    expected = (
        f"1 validation error detected: Value '[{bad_id}]' at 'campaignIds' failed to satisfy "
        "constraint: Member must satisfy constraint: [Member must have length less than or equal "
        "to 256, Member must have length greater than or equal to 1, Member must satisfy regular "
        "expression pattern: [-:/a-zA-Z0-9]+]"
    )
    assert err["Message"] == expected, f"expected message {expected!r}, got {err['Message']!r}"


def _error(fn):
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
