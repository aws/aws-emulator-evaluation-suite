"""create-prompt-router-duplicate-name-conflict-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-prompt-router-duplicate-name-conflict-rejected"
GROUP = "overly-permissive"
SERVICES = ["bedrock"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreatePromptRouter reusing an existing router's name returns ValidationException with the exact
    'already exists' message and leaves one unchanged router listed under the name, while a fresh name
    creates a router GetPromptRouter reads back."""
    bedrock = ctx.client("bedrock")
    models, fallback = _models_from_a_default_router(bedrock)

    name = ctx.unique_name("sim2real-duproutrer-")
    first_resp = bedrock.create_prompt_router(
        promptRouterName=name,
        models=models,
        routingCriteria={"responseQualityDifference": 10.0},
        fallbackModel=fallback,
    )
    first_arn = first_resp["promptRouterArn"]
    ctx.on_cleanup(lambda: _best_effort_delete(bedrock, first_arn))

    # Negative: reusing the same name is rejected.
    code, message = _error_code_and_message(
        lambda: bedrock.create_prompt_router(
            promptRouterName=name,
            models=models,
            routingCriteria={"responseQualityDifference": 20.0},
            fallbackModel=fallback,
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    expected_message = (
        f"Failed to create the resource because the prompt router with name {name} already exists."
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect absent: exactly one router with this name exists, and it is unchanged.
    # Freshly created/rejected resources can lag slightly behind list-consistency,
    # so poll with a bounded retry rather than trusting a single read.
    matches = _matching_routers(bedrock, name)
    deadline = time.monotonic() + 30.0
    while len(matches) != 1 and time.monotonic() < deadline:
        time.sleep(2.0)
        matches = _matching_routers(bedrock, name)
    assert len(matches) == 1, f"expected exactly 1 router named {name!r}, found {len(matches)}"
    assert matches[0]["promptRouterArn"] == first_arn, (
        f"expected the untouched router {first_arn!r}, got {matches[0]['promptRouterArn']!r}"
    )
    assert matches[0]["routingCriteria"]["responseQualityDifference"] == 10.0, (
        "the rejected duplicate must not have altered the original router's routingCriteria"
    )

    # Positive control: a fresh, unused name creates cleanly.
    other_name = ctx.unique_name("sim2real-duproutrer-other-")
    other_resp = bedrock.create_prompt_router(
        promptRouterName=other_name,
        models=models,
        routingCriteria={"responseQualityDifference": 10.0},
        fallbackModel=fallback,
    )
    other_arn = other_resp["promptRouterArn"]
    ctx.on_cleanup(lambda: _best_effort_delete(bedrock, other_arn))
    got_other = bedrock.get_prompt_router(promptRouterArn=other_arn)
    assert got_other["promptRouterName"] == other_name, (
        f"expected {other_name!r}, got {got_other['promptRouterName']!r}"
    )


def _error_code_and_message(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _matching_routers(bedrock, name):
    return [
        s
        for s in bedrock.list_prompt_routers(type="custom").get("promptRouterSummaries", [])
        if s["promptRouterName"] == name
    ]


def _best_effort_delete(bedrock, router_arn):
    from botocore.exceptions import ClientError

    try:
        bedrock.delete_prompt_router(promptRouterArn=router_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _models_from_a_default_router(bedrock):
    """Reuse the models and fallback of one of AWS's default prompt routers, which support
    intelligent prompt routing in the region regardless of per-model access grants or lifecycle.
    """
    resp = bedrock.list_prompt_routers(type="default")
    summaries = resp.get("promptRouterSummaries", [])
    assert summaries, "expected at least one default prompt router in this account/region"
    router = summaries[0]
    return router["models"], router["fallbackModel"]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
