"""delete-enforced-guardrail-configuration-restores-default."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "delete-enforced-guardrail-configuration-restores-default"
GROUP = "server-side"
SERVICES = ["bedrock"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control", "resource:account-singleton:bedrock-enforced-guardrail")
def run(ctx) -> None:
    """DeleteEnforcedGuardrailConfiguration removes server-side enforcement such
    that ListEnforcedGuardrailsConfiguration no longer reports the guardrail as
    enforced (the singleton list goes from one entry back to empty)."""
    bedrock = ctx.client("bedrock")

    guardrail_name = ctx.unique_name("sim2real-delcfg-gr-")
    created = bedrock.create_guardrail(
        name=guardrail_name,
        blockedInputMessaging="Input blocked by test guardrail.",
        blockedOutputsMessaging="Output blocked by test guardrail.",
        wordPolicyConfig={"wordsConfig": [{"text": ctx.unique_name("bannedword").replace("-", "")}]},
        tags=[{"key": "sim2real", "value": "delete-enforced-guardrail-configuration-restores-default"}],
    )
    guardrail_id = created["guardrailId"]
    ctx.on_cleanup(lambda: bedrock.delete_guardrail(guardrailIdentifier=guardrail_id))

    _poll_until(
        lambda: bedrock.get_guardrail(guardrailIdentifier=guardrail_id)["status"],
        lambda status: status in ("READY", "FAILED"),
        timeout_s=60.0,
        interval_s=3.0,
    )
    ready_status = bedrock.get_guardrail(guardrailIdentifier=guardrail_id)["status"]
    assert ready_status == "READY", f"expected the guardrail to reach READY, got {ready_status!r}"

    version = bedrock.create_guardrail_version(guardrailIdentifier=guardrail_id)["version"]
    version_status = _poll_until(
        lambda: bedrock.get_guardrail(guardrailIdentifier=guardrail_id, guardrailVersion=version)["status"],
        lambda status: status in ("READY", "FAILED"),
        timeout_s=60.0,
        interval_s=3.0,
    )
    assert version_status == "READY", f"expected guardrail version {version!r} to reach READY, got {version_status!r}"

    original = bedrock.list_enforced_guardrails_configuration().get("guardrailsConfig", [])
    original_config = original[0] if original else None

    def _restore_original() -> None:
        if original_config:
            bedrock.put_enforced_guardrail_configuration(
                configId=original_config["configId"],
                guardrailInferenceConfig={
                    "guardrailIdentifier": original_config["guardrailId"],
                    "guardrailVersion": original_config["guardrailVersion"],
                },
            )

    ctx.on_cleanup(_restore_original)

    put_kwargs: dict = {
        "guardrailInferenceConfig": {"guardrailIdentifier": guardrail_id, "guardrailVersion": version}
    }
    if original_config:
        put_kwargs["configId"] = original_config["configId"]
    put_resp = bedrock.put_enforced_guardrail_configuration(**put_kwargs)
    config_id = put_resp["configId"]

    listed = _poll_until(
        lambda: bedrock.list_enforced_guardrails_configuration().get("guardrailsConfig", []),
        lambda cfgs: any(c["configId"] == config_id for c in cfgs),
        timeout_s=30.0,
        interval_s=2.0,
    )
    assert any(c["configId"] == config_id and c["guardrailId"] == guardrail_id for c in listed), (
        f"expected ListEnforcedGuardrailsConfiguration to report configId={config_id!r}; got {listed!r}"
    )

    bedrock.delete_enforced_guardrail_configuration(configId=config_id)

    after = _poll_until(
        lambda: bedrock.list_enforced_guardrails_configuration().get("guardrailsConfig", []),
        lambda cfgs: not any(c["configId"] == config_id for c in cfgs),
        timeout_s=30.0,
        interval_s=2.0,
    )
    assert not any(c["configId"] == config_id for c in after), (
        f"expected the deleted configId={config_id!r} to no longer be reported as enforced; got {after!r}"
    )

    try:
        bedrock.delete_enforced_guardrail_configuration(configId=config_id)
    except bedrock.exceptions.ResourceNotFoundException as err:
        message = err.response["Error"].get("Message")
        assert message == "No default guardrail configuration found for the specified config identifier.", (
            f"unexpected not-found message for the second delete of configId={config_id!r}: {message!r}"
        )
    else:
        raise AssertionError(
            f"expected a second delete of the already-deleted configId={config_id!r} "
            "to raise ResourceNotFoundException; it succeeded instead"
        )


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out after {timeout_s}s waiting for predicate; last observed value: {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
