"""get-recommendations-missing-campaign-and-recommender-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-recommendations-missing-campaign-and-recommender-rejected"
GROUP = "overly-permissive"
SERVICES = ["personalize-runtime"]


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetRecommendations naming neither campaignArn nor recommenderArn gets InvalidInputException
    "campaignArn or recommenderArn required.", while naming a nonexistent campaign gets the different
    does-not-exist message."""
    rt = ctx.client("personalize-runtime")
    user_id = ctx.unique_name("user-")

    err = _error(lambda: rt.get_recommendations(userId=user_id))
    code, msg = err["Code"], err["Message"]
    assert code == "InvalidInputException", f"expected InvalidInputException, got {code}"
    assert msg == "campaignArn or recommenderArn required.", f"expected the required-field message, got {msg!r}"

    # positive control: naming a syntactically valid but nonexistent campaignArn still raises
    # InvalidInputException (the code alone does not discriminate), but the message changes to
    # an ARN-existence complaint -- proving the assertion above is about naming neither field,
    # not a generic catch-all that would also swallow "resource not found".
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    campaign_arn = (
        f"arn:aws:personalize:{ctx.region}:{account_id}:campaign/"
        f"{ctx.unique_name('sim2real-personalize-nope-')}"
    )
    err2 = _error(lambda: rt.get_recommendations(campaignArn=campaign_arn, userId=user_id))
    code2, msg2 = err2["Code"], err2["Message"]
    assert code2 == "InvalidInputException", f"expected InvalidInputException, got {code2}"
    assert msg2 == f"{campaign_arn} does not exist or is not active yet.", (
        f"expected an ARN-existence message distinct from the required-field message, got {msg2!r}"
    )
    assert msg2 != msg, "positive control must fail for a different reason than the negative"


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
