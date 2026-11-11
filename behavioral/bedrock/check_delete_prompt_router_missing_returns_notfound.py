"""delete-prompt-router-missing-returns-notfound."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-prompt-router-missing-returns-notfound"
GROUP = "error-semantics"
SERVICES = ["bedrock"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """After a real prompt router is deleted, GetPromptRouter and a second DeletePromptRouter on its ARN
    both return ResourceNotFoundException 'Cannot find prompt router <arn>.' (a never-owned ARN is
    refused with AccessDeniedException first, so the check deletes a router it created).
    """
    bedrock = ctx.client("bedrock")
    models, fallback = _models_from_a_default_router(bedrock)
    name = ctx.unique_name("sim2real-bedrock-router-")

    created = bedrock.create_prompt_router(
        promptRouterName=name,
        models=models,
        fallbackModel=fallback,
        routingCriteria={"responseQualityDifference": 5},
        tags=[{"key": "sim2real", "value": "delete-prompt-router-missing-returns-notfound"}],
    )
    router_arn = created["promptRouterArn"]
    ctx.on_cleanup(lambda: _safe(lambda: bedrock.delete_prompt_router(promptRouterArn=router_arn)))

    # positive: deleting a real, currently-existing router succeeds
    bedrock.delete_prompt_router(promptRouterArn=router_arn)
    gone = _error(lambda: bedrock.get_prompt_router(promptRouterArn=router_arn))
    gone_expected = ("ResourceNotFoundException", f"Cannot find prompt router {router_arn}.")
    assert gone == gone_expected, (
        f"expected the real router to be gone after delete with {gone_expected!r}, got {gone!r}"
    )

    # negative: deleting the same deleted router ARN again is a not-found, not a silent no-op
    got = _error(lambda: bedrock.delete_prompt_router(promptRouterArn=router_arn))
    expected = ("ResourceNotFoundException", f"Cannot find prompt router {router_arn}.")
    assert got == expected, f"expected {expected!r}, got {got!r}"


def _models_from_a_default_router(bedrock):
    """Reuse the models/fallback of one of AWS's own default prompt routers, so the
    model selection is guaranteed to support intelligent prompt routing in this
    account/region without hardcoding a provider/model that may not be supported
    or enabled here.
    """
    resp = bedrock.list_prompt_routers(type="default")
    summaries = resp.get("promptRouterSummaries", [])
    assert summaries, "expected at least one default prompt router in this account/region"
    router = summaries[0]
    return router["models"], router["fallbackModel"]


def _error(fn):
    """Call fn() and return its error (code, message); a success raises, as the call must be refused."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message", "")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _safe(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
