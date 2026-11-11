"""describe-nonexistent-campaign-not-found."""
from __future__ import annotations
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-nonexistent-campaign-not-found"
GROUP = "error-semantics"
SERVICES = ["connectcampaigns"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeCampaign on a UUID-shaped id that was never created fails with ResourceNotFoundException
    "CampaignId not found <id>."."""
    cc = ctx.client("connectcampaigns")
    bogus_id = str(uuid.uuid4())
    code, message = _error_code_and_message(lambda: cc.describe_campaign(id=bogus_id))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    assert message == f"CampaignId not found {bogus_id}.", message


def _error_code_and_message(fn):
    """Call fn(); return its botocore error code and message. An unexpected SUCCESS raises, because
    an emulator ACCEPTING a lookup real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
