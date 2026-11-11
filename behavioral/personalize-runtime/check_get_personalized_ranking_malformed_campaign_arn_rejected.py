"""get-personalized-ranking-malformed-campaign-arn-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-personalized-ranking-malformed-campaign-arn-rejected"
GROUP = "overly-permissive"
SERVICES = ["personalize-runtime"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetPersonalizedRanking rejects a campaignArn that is not ARN-shaped with the exact pattern
    ValidationException, while a well-formed nonexistent ARN gets InvalidInputException "<arn> does not
    exist or is not active yet." instead."""
    rt = ctx.client("personalize-runtime")
    user_id = ctx.unique_name("user-")
    input_list = ["item-a", "item-b", "item-c"]

    error = _error(
        lambda: rt.get_personalized_ranking(campaignArn="not-an-arn", userId=user_id, inputList=input_list)
    )
    code, message = error.get("Code"), error.get("Message")
    assert code == "ValidationException", f"expected ValidationException, got {code}"
    assert message == (
        "1 validation error detected: Value at 'campaignArn' failed to satisfy constraint: "
        r"Member must satisfy regular expression pattern: arn:([a-z\d-]+):personalize:.*:.*:.+"
    ), f"expected the exact malformed-ARN message, got {message!r}"

    # positive control: a well-formed but nonexistent ARN passes format validation and
    # instead fails at the resource-lookup stage.
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    valid_format_arn = (
        f"arn:aws:personalize:{ctx.region}:{account_id}:campaign/"
        f"{ctx.unique_name('sim2real-personalize-nope-')}"
    )
    error2 = _error(
        lambda: rt.get_personalized_ranking(campaignArn=valid_format_arn, userId=user_id, inputList=input_list)
    )
    code2, message2 = error2.get("Code"), error2.get("Message")
    assert code2 == "InvalidInputException", f"expected InvalidInputException, got {code2}"
    assert message2 == f"{valid_format_arn} does not exist or is not active yet.", f"expected the exact nonexistent-campaign message, got {message2!r}"


def _error(fn):
    """Call fn(); return its botocore Error dict. An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
