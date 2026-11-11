"""concurrent-put-enforced-guardrail-configuration-last-write-wins."""
from __future__ import annotations

import threading
import time

from behavioral_harness import tags

CHECK = "concurrent-put-enforced-guardrail-configuration-last-write-wins"
GROUP = "concurrency"
SERVICES = ["bedrock"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:bedrock-enforced-guardrail")
def run(ctx) -> None:
    """Two concurrent PutEnforcedGuardrailConfiguration calls both succeed and the account
    settles on exactly one of the two submitted guardrail versions, never a corrupted mix."""
    bedrock = ctx.client("bedrock")

    prior = _get_enforced_config(bedrock)

    guardrail = bedrock.create_guardrail(
        name=ctx.unique_name("sim2real-bedrock-gr-"),
        blockedInputMessaging="Sorry, I can't help with that input.",
        blockedOutputsMessaging="Sorry, I can't help with that output.",
        wordPolicyConfig={"wordsConfig": [{"text": "sim2realblockedword"}]},
    )
    guardrail_arn = guardrail["guardrailArn"]
    ctx.on_cleanup(lambda: _safe_delete_guardrail(bedrock, guardrail_arn))

    _wait_guardrail_ready(ctx, bedrock, guardrail_arn)
    version_1 = _create_ready_version(ctx, bedrock, guardrail_arn)
    version_2 = _create_ready_version(ctx, bedrock, guardrail_arn)
    assert version_1 != version_2, f"expected two distinct guardrail versions, got version_1={version_1!r} version_2={version_2!r}"

    # The base write names a third version, so a final read of either racer's version proves a
    # racing write was applied rather than both dropped.
    version_0 = _create_ready_version(ctx, bedrock, guardrail_arn)
    base_kwargs: dict = {
        "guardrailInferenceConfig": {"guardrailIdentifier": guardrail_arn, "guardrailVersion": version_0}
    }
    if prior is not None:
        base_kwargs["configId"] = prior["configId"]
    base_resp = bedrock.put_enforced_guardrail_configuration(**base_kwargs)
    config_id = base_resp["configId"]

    ctx.on_cleanup(lambda: _restore_enforced_config(bedrock, prior, config_id))

    # No ConflictException is documented for a concurrent overwrite of this account singleton,
    # so both racing calls are expected to succeed.
    results: dict[str, object] = {}

    def _put(key: str, version: str) -> None:
        try:
            bedrock.put_enforced_guardrail_configuration(
                configId=config_id,
                guardrailInferenceConfig={"guardrailIdentifier": guardrail_arn, "guardrailVersion": version},
            )
            results[key] = "ok"
        except Exception as exc:  # noqa: BLE001
            results[key] = exc

    t1 = threading.Thread(target=_put, args=("v1", version_1))
    t2 = threading.Thread(target=_put, args=("v2", version_2))
    t1.start()
    t2.start()
    t1.join()
    t2.join()

    assert results["v1"] == "ok", f"put of version_1 unexpectedly failed: {results['v1']}"
    assert results["v2"] == "ok", f"put of version_2 unexpectedly failed: {results['v2']}"

    final_version = _wait_for_settled_version(
        bedrock, {version_1, version_2}, timeout_s=_budget_s(ctx, 60.0)
    )
    if final_version not in (version_1, version_2) and _budget_spent(ctx):
        raise TimeoutError("the enforced configuration settling on a put version: "
                           "the run budget ended first; not graded")
    assert final_version in (version_1, version_2), f"corrupted/unexpected final version: {final_version!r}"


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _wait_guardrail_ready(ctx, bedrock, guardrail_arn: str, version: str | None = None) -> None:
    """Poll GetGuardrail (bounded by ctx.time_left()) until the guardrail or version is READY."""
    kwargs = {"guardrailIdentifier": guardrail_arn} | ({"guardrailVersion": version} if version else {})
    deadline = time.monotonic() + _budget_s(ctx, 120.0)
    status = bedrock.get_guardrail(**kwargs)["status"]
    while status != "READY" and time.monotonic() < deadline:
        time.sleep(1)
        status = bedrock.get_guardrail(**kwargs)["status"]
    if status != "READY" and _budget_spent(ctx):
        raise TimeoutError(f"guardrail {guardrail_arn} version {version!r} READY: "
                           "the run budget ended first; not graded")
    assert status == "READY", f"guardrail {guardrail_arn} version {version!r} never became READY: {status!r}"


def _create_ready_version(ctx, bedrock, guardrail_arn: str) -> str:
    version = bedrock.create_guardrail_version(guardrailIdentifier=guardrail_arn)["version"]
    _wait_guardrail_ready(ctx, bedrock, guardrail_arn, version)
    _wait_guardrail_ready(ctx, bedrock, guardrail_arn)
    return version


def _get_enforced_config(bedrock):
    resp = bedrock.list_enforced_guardrails_configuration()
    items = resp.get("guardrailsConfig", [])
    if not items:
        return None
    item = items[0]
    return {
        "configId": item["configId"],
        "guardrailArn": item["guardrailArn"],
        "guardrailVersion": item["guardrailVersion"],
    }


def _restore_enforced_config(bedrock, prior, our_config_id: str) -> None:
    """Put back the account's enforced configuration; one already deleted needs nothing."""
    from botocore.exceptions import ClientError

    if prior is not None:
        bedrock.put_enforced_guardrail_configuration(
            configId=prior["configId"],
            guardrailInferenceConfig={
                "guardrailIdentifier": prior["guardrailArn"],
                "guardrailVersion": prior["guardrailVersion"],
            },
        )
        return
    try:
        bedrock.delete_enforced_guardrail_configuration(configId=our_config_id)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _safe_delete_guardrail(bedrock, guardrail_arn: str) -> None:
    """Delete the guardrail, retrying while the enforced configuration still holds it."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + 60.0
    while True:
        try:
            bedrock.delete_guardrail(guardrailIdentifier=guardrail_arn)
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code not in ("ConflictException", "ResourceInUseException") or time.monotonic() >= deadline:
                raise
            time.sleep(2)


def _wait_for_settled_version(bedrock, candidates: set, timeout_s: float) -> str:
    deadline = time.monotonic() + timeout_s
    version = ""
    while time.monotonic() < deadline:
        resp = bedrock.list_enforced_guardrails_configuration()
        items = resp.get("guardrailsConfig", [])
        if items:
            version = items[0].get("guardrailVersion", "")
            if version in candidates:
                return version
        time.sleep(1)
    return version


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
