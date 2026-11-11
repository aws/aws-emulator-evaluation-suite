"""list-campaigns-max-results-exceeds-limit-is-accepted."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-campaigns-max-results-exceeds-limit-is-accepted"
GROUP = "error-semantics"
SERVICES = ["connectcampaigns"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListCampaigns accepts maxResults=51, above the documented maximum of 50, and returns at most 51
    summaries, while maxResults=0 fails with ValidationException and its exact message."""
    campaigns = ctx.client("connectcampaigns")

    resp, code, message = _call(lambda: campaigns.list_campaigns(maxResults=51))
    assert code is None, f"expected maxResults=51 to be accepted, got {code}: {message}"
    assert isinstance(resp.get("campaignSummaryList"), list), resp
    assert len(resp["campaignSummaryList"]) <= 51, resp["campaignSummaryList"]

    # MaxResults is modeled with min:1/max:50, but botocore's client-side parameter
    # validator only enforces the `min` side of an integer range (see
    # botocore.validate.range_check / ParamValidator.VALIDATED_METADATA_ATTRS, which omits
    # `max`) -- so maxResults=0 would be rejected locally by ANY target, real or emulated,
    # telling us nothing about the service. Disable client-side validation so the request
    # actually reaches the wire and the rejection we assert on is the service's own.
    raw = _raw_client(ctx, "connectcampaigns")
    _, low_code, low_message = _call(lambda: raw.list_campaigns(maxResults=0))
    assert low_code == "ValidationException", (
        f"expected a server-side ValidationException for maxResults=0, got {low_code}: {low_message}"
    )
    assert low_message == (
        "1 validation error detected: Value at 'maxResults' failed to satisfy constraint: "
        "Member must have value greater than or equal to 1"
    ), low_message


def _call(fn):
    from botocore.exceptions import ClientError

    try:
        return fn(), None, None
    except ClientError as err:
        return None, err.response["Error"]["Code"], err.response["Error"].get("Message")


def _raw_client(ctx, service: str):
    from botocore.config import Config

    return ctx.client(service, config=Config(parameter_validation=False))


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

