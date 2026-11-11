"""prompt-router-lifecycle."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "prompt-router-lifecycle"
GROUP = "state-machine"
SERVICES = ["bedrock"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreatePromptRouter, GetPromptRouter returns the created router, DeletePromptRouter
    removes it so subsequent Get 404s."""
    bedrock = ctx.client("bedrock")
    router_name = ctx.unique_name("sim2real-router-")
    model_1 = f"arn:aws:bedrock:{ctx.region}::foundation-model/amazon.nova-lite-v1:0"
    model_2 = f"arn:aws:bedrock:{ctx.region}::foundation-model/amazon.nova-pro-v1:0"

    created = bedrock.create_prompt_router(
        promptRouterName=router_name,
        models=[{"modelArn": model_1}, {"modelArn": model_2}],
        routingCriteria={"responseQualityDifference": 10.0},
        fallbackModel={"modelArn": model_2},
        tags=[{"key": "sim2real", "value": CHECK}],
    )
    router_arn = created["promptRouterArn"]
    ctx.on_cleanup(
        lambda: _ignore_not_found(lambda: bedrock.delete_prompt_router(promptRouterArn=router_arn))
    )

    got = bedrock.get_prompt_router(promptRouterArn=router_arn)
    assert got["promptRouterArn"] == router_arn, (
        f"expected promptRouterArn {router_arn!r}, got {got['promptRouterArn']!r}"
    )
    assert got["promptRouterName"] == router_name, (
        f"expected promptRouterName {router_name!r}, got {got['promptRouterName']!r}"
    )
    assert got["status"] == "AVAILABLE", f"expected status AVAILABLE, got {got['status']!r}"
    assert got["type"] == "custom", f"expected type 'custom', got {got['type']!r}"
    got_models = {m["modelArn"] for m in got["models"]}
    assert got_models == {model_1, model_2}, (
        f"expected models {{{model_1!r}, {model_2!r}}}, got {got_models!r}"
    )

    bedrock.delete_prompt_router(promptRouterArn=router_arn)

    code, message = _error_after_delete(
        lambda: bedrock.get_prompt_router(promptRouterArn=router_arn), timeout_s=60.0, interval_s=2.0
    )
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException after delete, got {code!r}"
    )
    expected_message = f"Cannot find prompt router {router_arn}."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


def _error_after_delete(fn, timeout_s, interval_s):
    """Call fn() until it is refused; return the (code, message). Raises if it still succeeds
    when the timeout runs out."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            last = fn()
        except ClientError as e:
            err = e.response["Error"]
            return err["Code"], err.get("Message", "")
        time.sleep(interval_s)
    raise AssertionError(f"expected the call to be refused within {timeout_s}s, but it kept succeeding (last={last!r})")


def _ignore_not_found(fn) -> None:
    try:
        fn()
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
