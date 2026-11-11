"""enforced-guardrail-configuration-unknown-guardrail-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "enforced-guardrail-configuration-unknown-guardrail-rejected"
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


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control", "resource:account-singleton:bedrock-enforced-guardrail")
def run(ctx) -> None:
    """PutEnforcedGuardrailConfiguration on a well-formed but nonexistent guardrail returns
    ResourceNotFoundException 'The guardrail provided in the request does not exist.' and leaves the
    configuration unchanged, while a real guardrail version is accepted and listed.
    """
    bedrock = ctx.client("bedrock")

    # The enforced-guardrail configuration is account-level state: snapshot it,
    # restore it in cleanup, and grade only against that snapshot.
    original = _snapshot_and_restore_enforced_configs(ctx, bedrock)

    bogus_guardrail_id = "zzzznonexistent0001"  # well-formed (lowercase alnum) but not a real guardrail
    code, message = _error(
        lambda: bedrock.put_enforced_guardrail_configuration(
            guardrailInferenceConfig={
                "guardrailIdentifier": bogus_guardrail_id,
                "guardrailVersion": "1",
            }
        )
    )
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for a non-existent guardrail, got {code!r}"
    )
    assert message == "The guardrail provided in the request does not exist.", (
        f"unexpected ResourceNotFoundException message {message!r}"
    )

    # Effect absent: the singleton configuration was not created by the failed call.
    after_failed_put = bedrock.list_enforced_guardrails_configuration()["guardrailsConfig"]
    assert after_failed_put == original, (
        "a failed PutEnforcedGuardrailConfiguration must not change the configurations, "
        f"got {after_failed_put!r} vs before {original!r}"
    )

    # Positive control: a real guardrail/version is accepted.
    name = ctx.unique_name("sim2real-bedrock-enforced-neg-")
    created = bedrock.create_guardrail(
        name=name,
        blockedInputMessaging="This input is blocked.",
        blockedOutputsMessaging="This output is blocked.",
        wordPolicyConfig={"wordsConfig": [{"text": "sim2realforbiddenterm"}]},
        tags=[{"key": "sim2real", "value": "enforced-guardrail-configuration-unknown-guardrail-rejected"}],
    )
    guardrail_id = created["guardrailId"]
    ctx.on_cleanup(lambda: bedrock.delete_guardrail(guardrailIdentifier=guardrail_id))

    version = bedrock.create_guardrail_version(guardrailIdentifier=guardrail_id)["version"]
    _wait_guardrail_version_ready(ctx, bedrock, guardrail_id, version)

    put_resp = bedrock.put_enforced_guardrail_configuration(
        guardrailInferenceConfig={"guardrailIdentifier": guardrail_id, "guardrailVersion": version}
    )
    config_id = put_resp["configId"]
    ctx.on_cleanup(lambda: bedrock.delete_enforced_guardrail_configuration(configId=config_id))

    listed = [
        c for c in bedrock.list_enforced_guardrails_configuration()["guardrailsConfig"]
        if c["configId"] == config_id
    ]
    assert len(listed) == 1 and listed[0]["guardrailId"] == guardrail_id, (
        f"positive control: a real guardrail should have been accepted and listed, got {listed!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
