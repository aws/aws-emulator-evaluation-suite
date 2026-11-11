"""e2e-enforced-guardrail-blocks-then-lifts."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-enforced-guardrail-blocks-then-lifts"
GROUP = "server-side"
SERVICES = ["bedrock"]

_BLOCKED_MARKER = "GUARDRAIL-ENFORCED-BLOCK-MARKER-9f21"
_BLOCKED_WORD = "zzqxenforcedblockedword"


def _cross_region_model_id(region: str) -> str:
    # On-demand Converse for Nova Micro requires the cross-region inference profile ID
    # (a "us."/"eu." prefix on the model ID) in regions where direct on-demand
    # invocation of the bare model ID isn't supported.
    if region.startswith("us-"):
        return "us.amazon.nova-micro-v1:0"
    if region.startswith("eu-"):
        return "eu.amazon.nova-micro-v1:0"
    return "amazon.nova-micro-v1:0"


@tags("axis:happy-path", "cap:c4", "cap:c7", "concern:data-plane", "dp:api", "plane:data", "resource:account-singleton:bedrock-enforced-guardrail")
def run(ctx) -> None:
    """While a guardrail is enforced account-wide by PutEnforcedGuardrailConfiguration, an InvokeModel
    naming no guardrail returns its blocked message; after the configuration is deleted the same call
    returns non-empty text without that message."""
    bedrock = ctx.client("bedrock")
    runtime = ctx.client("bedrock-runtime")
    model_id = _cross_region_model_id(ctx.region)

    name = ctx.unique_name("sim2real-behav-enforced-").replace("-", "_")
    created = bedrock.create_guardrail(
        name=name,
        blockedInputMessaging=_BLOCKED_MARKER,
        blockedOutputsMessaging=_BLOCKED_MARKER,
        wordPolicyConfig={"wordsConfig": [{"text": _BLOCKED_WORD}]},
        tags=[{"key": "sim2real", "value": CHECK}],
    )
    guardrail_id = created["guardrailId"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: bedrock.delete_guardrail(guardrailIdentifier=guardrail_id)))

    _poll_until(
        lambda: bedrock.get_guardrail(guardrailIdentifier=guardrail_id)["status"],
        lambda s: s in ("READY", "FAILED"),
        timeout_s=120,
    )
    status = bedrock.get_guardrail(guardrailIdentifier=guardrail_id)["status"]
    assert status == "READY", f"guardrail failed to become READY: {status}"

    version = bedrock.create_guardrail_version(guardrailIdentifier=guardrail_id)["version"]

    # The numbered version itself must independently reach READY before it can be
    # enforced -- polling only the DRAFT's status above is not sufficient.
    _poll_until(
        lambda: bedrock.get_guardrail(guardrailIdentifier=guardrail_id, guardrailVersion=version)["status"],
        lambda s: s in ("READY", "FAILED"),
        timeout_s=120,
    )
    version_status = bedrock.get_guardrail(guardrailIdentifier=guardrail_id, guardrailVersion=version)["status"]
    assert version_status == "READY", f"guardrail version failed to become READY: {version_status}"

    put_resp = bedrock.put_enforced_guardrail_configuration(
        guardrailInferenceConfig={"guardrailIdentifier": guardrail_id, "guardrailVersion": version}
    )
    config_id = put_resp["configId"]
    ctx.on_cleanup(
        lambda: _ignore_not_found(lambda: bedrock.delete_enforced_guardrail_configuration(configId=config_id))
    )

    # Enforcement is account-level and does not need to be referenced in the call.
    def _invoke():
        resp = runtime.converse(
            modelId=model_id,
            messages=[
                {
                    "role": "user",
                    "content": [{"text": f"Please explain what {_BLOCKED_WORD} means in one sentence."}],
                }
            ],
        )
        return resp["output"]["message"]["content"][0]["text"]

    blocked_text = _poll_until(_invoke, lambda body: _BLOCKED_MARKER in body, timeout_s=90, interval_s=5)
    assert _BLOCKED_MARKER in blocked_text, (
        f"expected the account-enforced guardrail to intervene and return the configured "
        f"blockedOutputsMessaging marker {_BLOCKED_MARKER!r}; got {blocked_text!r}"
    )

    # Lift the enforcement.
    bedrock.delete_enforced_guardrail_configuration(configId=config_id)

    unblocked_text = _poll_until(_invoke, lambda body: _BLOCKED_MARKER not in body, timeout_s=90, interval_s=5)
    assert _BLOCKED_MARKER not in unblocked_text, (
        f"expected lifting the enforced configuration to stop intervention on the identical "
        f"call, but the blocked marker {_BLOCKED_MARKER!r} still appeared in {unblocked_text!r}"
    )
    assert unblocked_text.strip() != "", (
        "expected a real, non-empty model completion once enforcement was lifted; got an empty string"
    )


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value: {last}")


def _ignore_not_found(fn):
    try:
        fn()
    except ClientError as err:
        if err.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

