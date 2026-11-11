"""get-action-recommendations-malformed-campaign-arn-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-action-recommendations-malformed-campaign-arn-rejected"
GROUP = "overly-permissive"
SERVICES = ["personalize-runtime"]


_PATTERN_MESSAGE = (
    "1 validation error detected: Value at 'campaignArn' failed to satisfy constraint: "
    r"Member must satisfy regular expression pattern: arn:([a-z\d-]+):personalize:.*:.*:.+"
)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetActionRecommendations rejects a campaignArn that is not ARN-shaped with the exact pattern
    ValidationException, while a well-formed nonexistent ARN gets InvalidInputException "<arn> does not
    exist or is not active yet." instead."""
    rt = ctx.client("personalize-runtime")
    user_id = ctx.unique_name("user-")

    err = _error(lambda: rt.get_action_recommendations(campaignArn="not-an-arn", userId=user_id))
    assert err["Code"] == "ValidationException", f"expected ValidationException, got {err!r}"
    assert err["Message"] == _PATTERN_MESSAGE, f"unexpected ValidationException message {err['Message']!r}"

    # positive control: a well-formed but nonexistent ARN passes format validation and
    # instead fails at the resource-lookup stage.
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    valid_format_arn = (
        f"arn:aws:personalize:{ctx.region}:{account_id}:campaign/"
        f"{ctx.unique_name('sim2real-personalize-nope-')}"
    )
    err2 = _error(lambda: rt.get_action_recommendations(campaignArn=valid_format_arn, userId=user_id))
    assert err2["Code"] == "InvalidInputException", f"expected InvalidInputException, got {err2!r}"
    assert err2["Message"] == f"{valid_format_arn} does not exist or is not active yet.", (
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
