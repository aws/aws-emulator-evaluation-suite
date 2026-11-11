"""delete-provisioned-throughput-missing-conflict-not-notfound."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-provisioned-throughput-missing-conflict-not-notfound"
GROUP = "error-semantics"
SERVICES = ["bedrock"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteProvisionedModelThroughput and GetProvisionedModelThroughput on a nonexistent name-form
    provisionedModelId return ResourceNotFoundException naming it as not found, not ConflictException,
    while a guardrail created and deleted in the same run reads back as gone.
    """
    bedrock = ctx.client("bedrock")
    bogus_id = ctx.unique_name("sim2real-bedrock-noprov-")

    got = _error(lambda: bedrock.delete_provisioned_model_throughput(provisionedModelId=bogus_id))
    expected = (
        "ResourceNotFoundException",
        f"Provisioned model with the provided name {bogus_id} was not found.",
    )
    assert got == expected, f"expected {expected!r}, got {got!r}"

    # effect absent: the failed delete did not conjure a provisioned-throughput
    # record for this identifier
    get_got = _error(lambda: bedrock.get_provisioned_model_throughput(provisionedModelId=bogus_id))
    get_expected = (
        "ResourceNotFoundException",
        f"Provisioned model with the provided name {bogus_id} was not found.",
    )
    assert get_got == get_expected, (
        f"expected the bogus provisioned-model identifier to remain absent with {get_expected!r}, got {get_got!r}"
    )

    # Positive control: a guardrail create+delete succeeds, so Delete* calls are not refused
    # wholesale (a real Provisioned Throughput bills per model-unit hour).
    guardrail_name = ctx.unique_name("sim2real-bedrock-ctrl-gr-")
    created = bedrock.create_guardrail(
        name=guardrail_name,
        blockedInputMessaging="Sorry, this input is blocked.",
        blockedOutputsMessaging="Sorry, this output is blocked.",
        wordPolicyConfig={"wordsConfig": [{"text": "sim2realforbiddenword"}]},
    )
    guardrail_id = created["guardrailId"]
    ctx.on_cleanup(lambda: _safe(lambda: bedrock.delete_guardrail(guardrailIdentifier=guardrail_id)))
    bedrock.delete_guardrail(guardrailIdentifier=guardrail_id)

    # Prove the control delete actually took effect (deletion may be briefly
    # eventually consistent) rather than trusting a 200 that could no-op.
    control_expected = ("ResourceNotFoundException", "This guardrail does not exist.")
    control = _poll_until(
        lambda: _probe_error(lambda: bedrock.get_guardrail(guardrailIdentifier=guardrail_id)),
        lambda got: got == control_expected,
        timeout_s=30.0,
        interval_s=2.0,
    )
    assert control == control_expected, (
        f"expected the deleted control guardrail to be gone with {control_expected!r}, got {control!r}"
    )


def _error(fn):
    """Call fn() and return its error (code, message); a success raises, as the call must be refused."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _probe_error(fn):
    """Like _error, but tolerates transient success while polling for eventual
    disappearance: a success returns the "present" marker, which no (code, message)
    pair equals, so the caller keeps waiting and a timeout names it."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message", "")
    return "present"


def _safe(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _poll_until(probe, predicate, timeout_s=30.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
