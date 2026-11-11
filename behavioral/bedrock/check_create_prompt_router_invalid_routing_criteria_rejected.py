"""create-prompt-router-invalid-routing-criteria-rejected."""
from __future__ import annotations

from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-prompt-router-invalid-routing-criteria-rejected"
GROUP = "state-machine"
SERVICES = ["bedrock"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreatePromptRouter with an out-of-range responseQualityDifference is rejected."""
    bedrock = ctx.client("bedrock")
    lite_arn = f"arn:aws:bedrock:{ctx.region}::foundation-model/amazon.nova-lite-v1:0"
    pro_arn = f"arn:aws:bedrock:{ctx.region}::foundation-model/amazon.nova-pro-v1:0"
    name = ctx.unique_name("sim2real-promptrouter-range-")

    # responseQualityDifference must be a multiple of 5; 7 is not.
    code, message = _error_code_and_message(
        lambda: bedrock.create_prompt_router(
            promptRouterName=name,
            models=[{"modelArn": pro_arn}, {"modelArn": lite_arn}],
            fallbackModel={"modelArn": lite_arn},
            routingCriteria={"responseQualityDifference": 7},
        )
    )
    expected = ("ValidationException", "Response quality difference must be a value multiple of 5")
    assert (code, message) == expected, f"expected {expected!r}, got {(code, message)!r}"

    # effect absent: no router with this name was created.
    matches = [s for s in _list_all_routers(bedrock) if s["promptRouterName"] == name]
    assert matches == [], f"expected no router named {name!r}, found {matches}"

    # positive control: the same name with a valid routing criteria succeeds.
    resp = bedrock.create_prompt_router(
        promptRouterName=name,
        models=[{"modelArn": pro_arn}, {"modelArn": lite_arn}],
        fallbackModel={"modelArn": lite_arn},
        routingCriteria={"responseQualityDifference": 10},
        tags=[{"key": "sim2real", "value": "create-prompt-router-invalid-routing-criteria-rejected"}],
    )
    router_arn = resp["promptRouterArn"]
    ctx.on_cleanup(lambda: _safe_delete_router(bedrock, router_arn))

    got = bedrock.get_prompt_router(promptRouterArn=router_arn)
    assert got["promptRouterName"] == name, f"expected name {name!r}, got {got['promptRouterName']!r}"
    assert got["status"] == "AVAILABLE", f"expected AVAILABLE, got {got['status']!r}"


def _list_all_routers(bedrock) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    kwargs: dict[str, Any] = {}
    while True:
        resp = bedrock.list_prompt_routers(**kwargs)
        out.extend(resp.get("promptRouterSummaries", []))
        token = resp.get("nextToken")
        if not token:
            return out
        kwargs["nextToken"] = token


def _safe_delete_router(bedrock, router_arn: str) -> None:
    try:
        bedrock.delete_prompt_router(promptRouterArn=router_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _error_code_and_message(fn: Callable[[], Any]) -> tuple[str, str | None]:
    """Call fn(); return its botocore (Code, Message). An unexpected success raises, because
    accepting input AWS refuses must fail as such, not as an error-code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
