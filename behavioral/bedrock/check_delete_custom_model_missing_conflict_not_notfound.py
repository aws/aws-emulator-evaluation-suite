"""delete-custom-model-missing-conflict-not-notfound."""
from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-custom-model-missing-conflict-not-notfound"
GROUP = "error-semantics"
SERVICES = ["bedrock"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteCustomModel on a pattern-valid custom-model ARN that was never created returns
    ResourceNotFoundException 'Custom model not found.', not ConflictException, while a guardrail
    created and deleted in the same run is gone afterwards.
    """
    bedrock = ctx.client("bedrock")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    # Must be pattern-valid (custom-model/<provider>.<model>/<12-char suffix>) or the
    # service rejects it with ValidationException before ever looking the model up.
    suffix = uuid.uuid4().hex[:12]
    bogus_model_arn = (
        f"arn:aws:bedrock:{ctx.region}:{account_id}:custom-model/"
        f"amazon.titan-text-express-v1/{suffix}"
    )

    got = _error(lambda: bedrock.delete_custom_model(modelIdentifier=bogus_model_arn))
    expected = ("ResourceNotFoundException", "Custom model not found.")
    assert got == expected, f"expected {expected!r}, got {got!r}"

    # Positive control: a guardrail create+delete succeeds, so Delete* calls are not refused
    # wholesale (a custom model needs a model package or a finished customization job).
    guardrail_name = ctx.unique_name("sim2real-bedrock-ctrl-gr-")
    created = bedrock.create_guardrail(
        name=guardrail_name,
        blockedInputMessaging="Sorry, this input is blocked.",
        blockedOutputsMessaging="Sorry, this output is blocked.",
        wordPolicyConfig={"wordsConfig": [{"text": "sim2realforbiddenword"}]},
        tags=[{"key": "sim2real", "value": "delete-custom-model-missing-conflict-not-notfound"}],
    )
    guardrail_id = created["guardrailId"]
    ctx.on_cleanup(lambda: _safe(lambda: bedrock.delete_guardrail(guardrailIdentifier=guardrail_id)))
    bedrock.delete_guardrail(guardrailIdentifier=guardrail_id)

    # The delete above is otherwise unasserted: prove it actually took, via an
    # independent read, allowing briefly for eventual consistency.
    _wait_gone(lambda: bedrock.get_guardrail(guardrailIdentifier=guardrail_id))


def _error(fn):
    """Call fn() and return its error (code, message); a success raises, as the call must be
    refused."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _safe(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _wait_gone(fn, *, timeout_s=30.0, interval_s=2.0) -> None:
    deadline = time.monotonic() + timeout_s
    last_code = None
    while time.monotonic() < deadline:
        try:
            fn()
        except ClientError as exc:
            last_code = exc.response["Error"]["Code"]
            if last_code == "ResourceNotFoundException":
                return
        else:
            last_code = None
        time.sleep(interval_s)
    raise AssertionError(
        f"expected the deleted resource to be gone within {timeout_s}s, last saw {last_code!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
