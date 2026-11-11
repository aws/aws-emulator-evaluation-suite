"""delete-default-prompt-router-rejected."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "delete-default-prompt-router-rejected"
GROUP = "overly-permissive"
SERVICES = ["bedrock"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Attempting to delete one of Bedrock's built-in default (system) prompt routers
    is rejected with ValidationException and it remains listed; deleting a
    custom router created in this run succeeds (positive control)."""
    bedrock = ctx.client("bedrock")

    defaults = bedrock.list_prompt_routers(type="default").get("promptRouterSummaries", [])
    if not defaults:
        raise AssertionError(
            "this account/region exposes no built-in default prompt routers to probe "
            "the immutable-system-resource deletion boundary against"
        )
    default_arn = defaults[0]["promptRouterArn"]

    # Negative: default/system routers cannot be deleted through this API — the ARN
    # does not match the custom-router resource type DeletePromptRouter accepts.
    got = _error(lambda: bedrock.delete_prompt_router(promptRouterArn=default_arn))
    expected = ("ValidationException", "You don't have the permission to delete the default prompt router.")
    assert got == expected, f"expected {expected!r}, got {got!r}"

    # Effect absent: the default router is still listed afterwards.
    still_there = [
        s
        for s in bedrock.list_prompt_routers(type="default").get("promptRouterSummaries", [])
        if s["promptRouterArn"] == default_arn
    ]
    assert len(still_there) == 1, (
        f"expected the default router {default_arn!r} to still be listed after the "
        f"rejected delete, found {len(still_there)} matching entries"
    )

    # Positive control: a custom router created in this run deletes cleanly. Reuse the
    # default router's own models/fallback (rather than probing ListFoundationModels for
    # a hardcoded candidate list) so model selection follows what this account/region
    # already has working for intelligent prompt routing.
    custom_name = ctx.unique_name("sim2real-defrouter-control-")
    custom_resp = bedrock.create_prompt_router(
        promptRouterName=custom_name,
        models=defaults[0]["models"],
        routingCriteria={"responseQualityDifference": 10.0},
        fallbackModel=defaults[0]["fallbackModel"],
        tags=[{"key": "sim2real", "value": CHECK}],
    )
    custom_arn = custom_resp["promptRouterArn"]
    ctx.on_cleanup(lambda: _best_effort_delete(bedrock, custom_arn))

    bedrock.delete_prompt_router(promptRouterArn=custom_arn)
    gone = _error(lambda: bedrock.get_prompt_router(promptRouterArn=custom_arn))
    gone_expected = ("ResourceNotFoundException", f"Cannot find prompt router {custom_arn}.")
    assert gone == gone_expected, f"expected the custom router to be gone with {gone_expected!r}, got {gone!r}"


def _error(fn):
    """The AWS error (code, message) fn raises. Raises AssertionError if fn SUCCEEDS: an
    acceptance where AWS refuses must never read as an error-code mismatch."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as e:
        err = e.response["Error"]
        return err["Code"], err.get("Message", "")
    raise AssertionError("the call was ACCEPTED where a refusal was expected")


def _best_effort_delete(bedrock, router_arn):
    from botocore.exceptions import ClientError

    try:
        bedrock.delete_prompt_router(promptRouterArn=router_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
