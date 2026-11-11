"""prompt-router-unknown-model-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "prompt-router-unknown-model-rejected"
GROUP = "state-machine"
SERVICES = ["bedrock"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreatePromptRouter with a nonexistent fallbackModel ARN returns ValidationException 'The fallback
    model is not present in the list of models for routing.' and creates no router, while the same
    request with a listed fallback model creates an AVAILABLE router."""
    bedrock = ctx.client("bedrock")
    router_name = ctx.unique_name("sim2real-router-badmodel-")
    valid_model_1 = f"arn:aws:bedrock:{ctx.region}::foundation-model/amazon.nova-lite-v1:0"
    valid_model_2 = f"arn:aws:bedrock:{ctx.region}::foundation-model/amazon.nova-pro-v1:0"
    bogus_model = f"arn:aws:bedrock:{ctx.region}::foundation-model/does-not-exist.no-such-model-v9:0"

    code, message = _error(
        lambda: bedrock.create_prompt_router(
            promptRouterName=router_name,
            models=[{"modelArn": valid_model_1}, {"modelArn": valid_model_2}],
            routingCriteria={"responseQualityDifference": 10.0},
            fallbackModel={"modelArn": bogus_model},
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    expected_message = "The fallback model is not present in the list of models for routing."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # effect absent: no router with this name was created by the rejected request
    assert not _prompt_router_exists(bedrock, router_name), (
        f"router {router_name!r} should not exist after a rejected create, but it does"
    )

    # positive control: the identical request with a real fallback model succeeds
    created = bedrock.create_prompt_router(
        promptRouterName=router_name,
        models=[{"modelArn": valid_model_1}, {"modelArn": valid_model_2}],
        routingCriteria={"responseQualityDifference": 10.0},
        fallbackModel={"modelArn": valid_model_2},
        tags=[{"key": "sim2real", "value": "prompt-router-unknown-model-rejected"}],
    )
    router_arn = created["promptRouterArn"]
    ctx.on_cleanup(
        lambda: _ignore_not_found(lambda: bedrock.delete_prompt_router(promptRouterArn=router_arn))
    )
    got = bedrock.get_prompt_router(promptRouterArn=router_arn)
    assert got["status"] == "AVAILABLE", f"expected AVAILABLE, got {got['status']!r}"


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as e:
        err = e.response["Error"]
        return err["Code"], err.get("Message", "")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _ignore_not_found(fn) -> None:
    try:
        fn()
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _prompt_router_exists(bedrock, router_name: str) -> bool:
    paginator = bedrock.get_paginator("list_prompt_routers")
    for page in paginator.paginate():
        for summary in page.get("promptRouterSummaries", []):
            if summary.get("promptRouterName") == router_name:
                return True
    return False


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
