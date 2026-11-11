"""get-action-recommendations-missing-campaign-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-action-recommendations-missing-campaign-rejected"
GROUP = "overly-permissive"
SERVICES = ["personalize-runtime"]


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetActionRecommendations requires a campaignArn (it has no recommenderArn alternative).

    Unlike GetRecommendations, GetActionRecommendations only accepts campaignArn -- there is
    no alternate resource-reference field -- so omitting it must always be rejected.
    """
    rt = ctx.client("personalize-runtime")
    user_id = ctx.unique_name("user-")

    err = _error(lambda: rt.get_action_recommendations(userId=user_id))
    assert err["Code"] == "InvalidInputException", f"expected InvalidInputException, got {err!r}"
    assert err["Message"] == "The given campaign ARN is invalid: null", (
        f"unexpected missing-campaignArn message {err['Message']!r}"
    )

    # positive control: supplying a (nonexistent) campaignArn keeps the code but changes the
    # message to an ARN-existence complaint, proving the rejection above is specifically about
    # the missing campaignArn rather than a generic catch-all.
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    campaign_arn = (
        f"arn:aws:personalize:{ctx.region}:{account_id}:campaign/"
        f"{ctx.unique_name('sim2real-personalize-nope-')}"
    )
    err2 = _error(lambda: rt.get_action_recommendations(campaignArn=campaign_arn, userId=user_id))
    assert err2["Code"] == "InvalidInputException", f"expected InvalidInputException, got {err2!r}"
    assert err2["Message"] == f"{campaign_arn} does not exist or is not active yet.", (
        f"unexpected InvalidInputException message {err2['Message']!r}"
    )


def _error(fn):
    """Call fn(); return its botocore Error dict ({"Code", "Message", ...}). An unexpected SUCCESS
    raises, because an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
