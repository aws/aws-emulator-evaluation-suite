"""put-enforced-guardrail-configuration-applies-to-invoke."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "put-enforced-guardrail-configuration-applies-to-invoke"
GROUP = "server-side"
SERVICES = ["bedrock"]

_MODEL_ID = "amazon.nova-lite-v1:0"


@tags("axis:happy-path", "cap:c4", "cap:c7", "concern:data-plane", "dp:api", "plane:data", "resource:account-singleton:bedrock-enforced-guardrail")
def run(ctx) -> None:
    """InvokeModel naming no guardrail is not INTERVENED on the blocked word before enforcement; after
    PutEnforcedGuardrailConfiguration the same word returns INTERVENED and a benign prompt NONE, so
    the enforced configuration, applied server-side, causes the intervention.
    """
    # Three short billed nova-lite InvokeModel prompts against a model the account can use.
    bedrock = ctx.client("bedrock")
    bedrock_runtime = ctx.client("bedrock-runtime")
    banned_word = ctx.unique_name("zsim2realbanned").replace("-", "")

    def _invoke(text: str) -> dict:
        resp = bedrock_runtime.invoke_model(
            modelId=_MODEL_ID,
            contentType="application/json",
            accept="application/json",
            body=json.dumps(
                {
                    "messages": [{"role": "user", "content": [{"text": text}]}],
                    "inferenceConfig": {"maxTokens": 8},
                }
            ),
        )
        return json.loads(resp["body"].read())

    def _invoke_or_raise_access(text: str) -> dict:
        try:
            return _invoke(text)
        except Exception as err:  # noqa: BLE001
            code = getattr(err, "response", {}).get("Error", {}).get("Code") if hasattr(err, "response") else None
            if code == "AccessDeniedException":
                raise AssertionError(
                    f"model access not granted for {_MODEL_ID} in this account/region; "
                    "request access via the Bedrock console model-access page"
                ) from err
            raise

    baseline_body = _invoke_or_raise_access(f"Please discuss the topic {banned_word} in detail.")
    assert baseline_body.get("amazon-bedrock-guardrailAction") != "INTERVENED", (
        "expected the banned word to pass through un-intervened before any account-level "
        f"guardrail enforces it; got {baseline_body!r}"
    )

    guardrail_name = ctx.unique_name("sim2real-enforced-gr-")
    created = bedrock.create_guardrail(
        name=guardrail_name,
        blockedInputMessaging="Input blocked by test guardrail.",
        blockedOutputsMessaging="Output blocked by test guardrail.",
        wordPolicyConfig={"wordsConfig": [{"text": banned_word}]},
        tags=[{"key": "sim2real", "value": "enforced-guardrail-applies-to-invoke"}],
    )
    guardrail_id = created["guardrailId"]
    ctx.on_cleanup(lambda: bedrock.delete_guardrail(guardrailIdentifier=guardrail_id))

    _poll_until(
        lambda: bedrock.get_guardrail(guardrailIdentifier=guardrail_id)["status"],
        lambda status: status in ("READY", "FAILED"),
        timeout_s=60.0,
        interval_s=3.0,
    )
    status = bedrock.get_guardrail(guardrailIdentifier=guardrail_id)["status"]
    assert status == "READY", f"guardrail did not become READY, status={status}"

    version = bedrock.create_guardrail_version(guardrailIdentifier=guardrail_id)["version"]
    _poll_until(
        lambda: bedrock.get_guardrail(guardrailIdentifier=guardrail_id, guardrailVersion=version)["status"],
        lambda status: status in ("READY", "FAILED"),
        timeout_s=60.0,
        interval_s=3.0,
    )
    version_status = bedrock.get_guardrail(guardrailIdentifier=guardrail_id, guardrailVersion=version)["status"]
    assert version_status == "READY", f"guardrail version did not become READY, status={version_status}"

    original = bedrock.list_enforced_guardrails_configuration().get("guardrailsConfig", [])
    original_config = original[0] if original else None

    def _restore() -> None:
        current = bedrock.list_enforced_guardrails_configuration().get("guardrailsConfig", [])
        for cfg in current:
            bedrock.delete_enforced_guardrail_configuration(configId=cfg["configId"])
        if original_config:
            bedrock.put_enforced_guardrail_configuration(
                guardrailInferenceConfig={
                    "guardrailIdentifier": original_config["guardrailId"],
                    "guardrailVersion": original_config["guardrailVersion"],
                }
            )

    ctx.on_cleanup(_restore)

    put_resp = bedrock.put_enforced_guardrail_configuration(
        guardrailInferenceConfig={"guardrailIdentifier": guardrail_id, "guardrailVersion": version}
    )
    config_id = put_resp["configId"]

    _poll_until(
        lambda: bedrock.list_enforced_guardrails_configuration().get("guardrailsConfig", []),
        lambda cfgs: any(c["configId"] == config_id for c in cfgs),
        timeout_s=30.0,
        interval_s=2.0,
    )

    blocked_body = _invoke(f"Please discuss the topic {banned_word} in detail.")
    benign_body = _invoke("Please describe the weather today in a short sentence.")

    assert blocked_body.get("amazon-bedrock-guardrailAction") == "INTERVENED", (
        "expected the account-enforced guardrail to intervene on a prompt containing "
        f"the banned word even though InvokeModel specified no guardrail; got {blocked_body!r}"
    )
    assert benign_body.get("amazon-bedrock-guardrailAction") == "NONE", (
        "expected a benign prompt under the same enforced guardrail to pass through "
        f"un-intervened; got {benign_body!r}"
    )


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
