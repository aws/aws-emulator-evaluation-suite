"""enforced-guardrail-configuration-put-list-delete."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "enforced-guardrail-configuration-put-list-delete"
GROUP = "server-side"
SERVICES = ["bedrock"]


def _error(fn):
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError but the call succeeded: {result!r}")


def _snapshot_and_restore_enforced_configs(ctx, bedrock):
    """Snapshot the account-level enforced-guardrail configurations and register a
    cleanup that re-puts any original entry missing at the end of the check."""
    original = bedrock.list_enforced_guardrails_configuration()["guardrailsConfig"]

    def restore():
        present = {
            c["configId"] for c in bedrock.list_enforced_guardrails_configuration()["guardrailsConfig"]
        }
        for entry in original:
            if entry["configId"] in present:
                continue
            config = {"guardrailIdentifier": entry["guardrailArn"], "guardrailVersion": entry["guardrailVersion"]}
            for key in ("selectiveContentGuarding", "modelEnforcement"):
                if key in entry:
                    config[key] = entry[key]
            bedrock.put_enforced_guardrail_configuration(guardrailInferenceConfig=config)

    ctx.on_cleanup(restore)
    return original


def _delete_config_if_present(bedrock, config_id):
    listed = bedrock.list_enforced_guardrails_configuration()["guardrailsConfig"]
    if config_id in {c["configId"] for c in listed}:
        bedrock.delete_enforced_guardrail_configuration(configId=config_id)


def _config_ids(configs):
    return sorted(c["configId"] for c in configs)


def _wait_guardrail_version_ready(ctx, bedrock, guardrail_id, version, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = bedrock.get_guardrail(guardrailIdentifier=guardrail_id, guardrailVersion=version)
        if resp["status"] == "READY":
            return resp
        if resp["status"] == "FAILED":
            raise AssertionError(f"guardrail version {version} failed to become READY: {resp}")
        time.sleep(interval_s)
    raise AssertionError(f"guardrail version {version} never reached READY within {timeout_s}s")


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control", "resource:account-singleton:bedrock-enforced-guardrail")
def run(ctx) -> None:
    """PutEnforcedGuardrailConfiguration surfaces in the list; Delete removes it again."""
    bedrock = ctx.client("bedrock")

    # The enforced-guardrail configuration is account-level state: snapshot it,
    # restore it in cleanup, and grade only the entry this check creates.
    original = _snapshot_and_restore_enforced_configs(ctx, bedrock)

    name = ctx.unique_name("sim2real-bedrock-enforced-")
    created = bedrock.create_guardrail(
        name=name,
        blockedInputMessaging="This input is blocked.",
        blockedOutputsMessaging="This output is blocked.",
        wordPolicyConfig={"wordsConfig": [{"text": "sim2realforbiddenterm"}]},
        tags=[{"key": "sim2real", "value": "enforced-guardrail-configuration-put-list-delete"}],
    )
    guardrail_id = created["guardrailId"]
    ctx.on_cleanup(lambda: bedrock.delete_guardrail(guardrailIdentifier=guardrail_id))

    version = bedrock.create_guardrail_version(guardrailIdentifier=guardrail_id)["version"]
    _wait_guardrail_version_ready(ctx, bedrock, guardrail_id, version)

    put_resp = bedrock.put_enforced_guardrail_configuration(
        guardrailInferenceConfig={
            "guardrailIdentifier": guardrail_id,
            "guardrailVersion": version,
        }
    )
    config_id = put_resp["configId"]
    ctx.on_cleanup(lambda: _delete_config_if_present(bedrock, config_id))

    listed = [
        c for c in bedrock.list_enforced_guardrails_configuration()["guardrailsConfig"]
        if c["configId"] == config_id
    ]
    assert len(listed) == 1, f"expected exactly one listed entry with configId {config_id!r}, got {listed!r}"
    assert listed[0]["guardrailId"] == guardrail_id, (
        f"expected the listed guardrailId to be {guardrail_id!r}, got {listed[0]['guardrailId']!r}"
    )
    assert listed[0]["guardrailVersion"] == version, (
        f"expected the listed guardrailVersion to be {version!r}, got {listed[0]['guardrailVersion']!r}"
    )

    bedrock.delete_enforced_guardrail_configuration(configId=config_id)

    after_delete = bedrock.list_enforced_guardrails_configuration()["guardrailsConfig"]
    assert _config_ids(after_delete) == _config_ids(original), (
        f"expected the list to return to its pre-check entries {_config_ids(original)!r} after delete, "
        f"got {_config_ids(after_delete)!r}"
    )

    # The deleted configId is not just absent from the list -- it is dead: a second delete
    # against the same id must be rejected, not silently accepted as a no-op.
    code, message = _error(lambda: bedrock.delete_enforced_guardrail_configuration(configId=config_id))
    assert code == "ResourceNotFoundException", (
        f"expected a second delete of the same configId to fail with ResourceNotFoundException, got {code!r}"
    )
    assert message == "No default guardrail configuration found for the specified config identifier.", (
        f"unexpected ResourceNotFoundException message {message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
