"""delete-guardrail-with-enforced-config-blocked."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-guardrail-with-enforced-config-blocked"
GROUP = "overly-permissive"
SERVICES = ["bedrock"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control", "resource:account-singleton:bedrock-enforced-guardrail")
def run(ctx) -> None:
    """DeleteGuardrail on the guardrail registered by PutEnforcedGuardrailConfiguration returns the exact
    'cannot be deleted' ValidationException and its version stays READY, while an unenforced guardrail
    deletes, and deleting it again returns ResourceNotFoundException 'This guardrail does not exist.'"""
    bedrock = ctx.client("bedrock")

    enforced_id, enforced_version = _create_ready_guardrail_version(ctx, "sim2real-gr-enf-")
    free_id, _free_version = _create_ready_guardrail_version(ctx, "sim2real-gr-free-")

    config = bedrock.put_enforced_guardrail_configuration(
        guardrailInferenceConfig={
            "guardrailIdentifier": enforced_id,
            "guardrailVersion": enforced_version,
        }
    )
    config_id = config["configId"]
    ctx.on_cleanup(lambda: _delete_enforced_config_best_effort(ctx, config_id))

    got = _error(lambda: bedrock.delete_guardrail(guardrailIdentifier=enforced_id))
    expected = (
        "ValidationException",
        "The guardrail cannot be deleted because it is associated with an account-level or "
        "organization-level default guardrail configuration.",
    )
    assert got == expected, f"expected {expected!r}, got {got!r}"

    # Effect absent: the enforced guardrail version is still there.
    still_there = bedrock.get_guardrail(guardrailIdentifier=enforced_id, guardrailVersion=enforced_version)
    assert still_there["status"] == "READY", (
        f"expected the enforced guardrail version to remain READY after the rejected "
        f"delete, got status {still_there['status']!r}"
    )

    # Positive control: an unenforced sibling guardrail deletes without complaint
    # (delete is asynchronous, so poll until it's genuinely gone).
    bedrock.delete_guardrail(guardrailIdentifier=free_id)
    def _free_outcome():
        """The GetGuardrail error code once the guardrail is gone, else "present"."""
        try:
            bedrock.get_guardrail(guardrailIdentifier=free_id)
        except ClientError as exc:
            return exc.response["Error"]["Code"]
        return "present"

    _poll_until(
        _free_outcome,
        lambda code: code == "ResourceNotFoundException",
        timeout_s=60.0,
        interval_s=3.0,
    )

    # A second delete on the deleted free guardrail fails with the specific
    # not-found answer, not success.
    redelete = _error(lambda: bedrock.delete_guardrail(guardrailIdentifier=free_id))
    redelete_expected = ("ResourceNotFoundException", "This guardrail does not exist.")
    assert redelete == redelete_expected, (
        f"expected re-deleting the already-gone guardrail to raise "
        f"{redelete_expected!r}, got {redelete!r}"
    )


def _error(fn):
    """The AWS error (code, message) fn raises; a success raises, as the call must be refused."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message", "")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


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
        tags=[{"key": "sim2real", "value": "delete-guardrail-with-enforced-config-blocked"}],
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
        if code not in ("ResourceNotFoundException",):
            raise


def _delete_enforced_config_best_effort(ctx, config_id: str) -> None:
    bedrock = ctx.client("bedrock")
    try:
        bedrock.delete_enforced_guardrail_configuration(configId=config_id)
    except Exception as exc:  # noqa: BLE001
        code = getattr(exc, "response", {}).get("Error", {}).get("Code")
        if code != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
