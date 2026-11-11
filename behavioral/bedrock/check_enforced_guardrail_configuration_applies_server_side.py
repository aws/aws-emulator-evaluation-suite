"""enforced-guardrail-configuration-applies-server-side."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "enforced-guardrail-configuration-applies-server-side"
GROUP = "server-side"
SERVICES = ["bedrock"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control", "resource:account-singleton:bedrock-enforced-guardrail")
def run(ctx) -> None:
    """After PutEnforcedGuardrailConfiguration, ListEnforcedGuardrailsConfiguration reports exactly one
    account-level entry with the returned configId and the registered guardrail id and version: the
    configuration is stored and read back on a separate path."""
    bedrock = ctx.client("bedrock")

    before = bedrock.list_enforced_guardrails_configuration().get("guardrailsConfig", [])
    original_entry = before[0] if before else None

    guardrail_id, version = _create_ready_guardrail_version(ctx, "sim2real-gr-enforce-")

    config = bedrock.put_enforced_guardrail_configuration(
        guardrailInferenceConfig={"guardrailIdentifier": guardrail_id, "guardrailVersion": version}
    )
    config_id = config["configId"]

    def _restore():
        if original_entry is not None:
            bedrock.put_enforced_guardrail_configuration(
                guardrailInferenceConfig={
                    "guardrailIdentifier": original_entry["guardrailId"],
                    "guardrailVersion": original_entry["guardrailVersion"],
                }
            )
        else:
            try:
                bedrock.delete_enforced_guardrail_configuration(configId=config_id)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise

    ctx.on_cleanup(_restore)

    listed = bedrock.list_enforced_guardrails_configuration()["guardrailsConfig"]
    assert len(listed) == 1, f"expected exactly one account-enforced config, got {listed}"
    entry = listed[0]
    assert entry["configId"] == config_id, f"expected configId {config_id!r}, got {entry['configId']!r}"
    assert entry["guardrailId"] == guardrail_id, (
        f"expected guardrailId {guardrail_id!r}, got {entry['guardrailId']!r}"
    )
    assert entry["guardrailVersion"] == version, (
        f"expected guardrailVersion {version!r}, got {entry['guardrailVersion']!r}"
    )


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last={last}")


def _create_ready_guardrail_version(ctx, prefix: str):
    bedrock = ctx.client("bedrock")
    created = bedrock.create_guardrail(
        name=ctx.unique_name(prefix),
        blockedInputMessaging="This input is blocked.",
        blockedOutputsMessaging="This output is blocked.",
        wordPolicyConfig={"wordsConfig": [{"text": "sim2real-blocked-word"}]},
        tags=[{"key": "sim2real", "value": "enforced-guardrail-configuration-applies-server-side"}],
    )
    guardrail_id = created["guardrailId"]
    ctx.on_cleanup(lambda: _delete_guardrail_best_effort(ctx, guardrail_id))

    _poll_until(
        lambda: bedrock.get_guardrail(guardrailIdentifier=guardrail_id),
        lambda r: r["status"] == "READY",
        timeout_s=60.0,
        interval_s=3.0,
    )
    version_resp = bedrock.create_guardrail_version(guardrailIdentifier=guardrail_id)
    version = version_resp["version"]
    _poll_until(
        lambda: bedrock.get_guardrail(guardrailIdentifier=guardrail_id, guardrailVersion=version),
        lambda r: r["status"] == "READY",
        timeout_s=60.0,
        interval_s=3.0,
    )
    return guardrail_id, version


def _delete_guardrail_best_effort(ctx, guardrail_id: str) -> None:
    bedrock = ctx.client("bedrock")
    try:
        bedrock.delete_guardrail(guardrailIdentifier=guardrail_id)
    except Exception as exc:  # noqa: BLE001
        code = getattr(exc, "response", {}).get("Error", {}).get("Code")
        if code not in ("ResourceNotFoundException", "ResourceInUseException"):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
