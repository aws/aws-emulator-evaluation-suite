"""get-recommendations-nonexistent-campaign-not-found."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-recommendations-nonexistent-campaign-not-found"
GROUP = "error-semantics"
SERVICES = ["personalize-runtime"]


_PATTERN_MESSAGE = (
    "1 validation error detected: Value at 'campaignArn' failed to satisfy constraint: "
    r"Member must satisfy regular expression pattern: arn:([a-z\d-]+):personalize:.*:.*:.+"
)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetRecommendations on a well-formed never-created campaignArn gets InvalidInputException "<arn>
    does not exist or is not active yet.", while a malformed ARN gets the exact pattern
    ValidationException."""
    rt = ctx.client("personalize-runtime")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    user_id = ctx.unique_name("user-")
    campaign_arn = (
        f"arn:aws:personalize:{ctx.region}:{account_id}:campaign/"
        f"{ctx.unique_name('sim2real-personalize-nope-')}"
    )

    err = _error(lambda: rt.get_recommendations(campaignArn=campaign_arn, userId=user_id))
    assert err["Code"] == "InvalidInputException", f"expected InvalidInputException, got {err!r}"
    assert err["Message"] == f"{campaign_arn} does not exist or is not active yet.", (
        f"unexpected InvalidInputException message {err['Message']!r}"
    )

    # positive control: an ARN that fails the format check entirely takes a different,
    # earlier failure path (ValidationException), proving the assertion above is really
    # about resource existence and not merely "any bad input yields the same code".
    err2 = _error(lambda: rt.get_recommendations(campaignArn="not-an-arn", userId=user_id))
    assert err2["Code"] == "ValidationException", f"expected ValidationException, got {err2!r}"
    assert err2["Message"] == _PATTERN_MESSAGE, f"unexpected ValidationException message {err2['Message']!r}"


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
