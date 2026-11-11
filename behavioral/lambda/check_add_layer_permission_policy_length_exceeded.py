"""add-layer-permission-policy-length-exceeded."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "add-layer-permission-policy-length-exceeded"
GROUP = "error-semantics"
SERVICES = ["lambda"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Adding layer-version permission statements past the 20KB resource-policy limit is rejected
    with PolicyLengthExceededException (AddLayerVersionPermission)."""
    lam = ctx.client("lambda")

    layer_name = ctx.unique_name("sim2real-behav-layer-")
    published = lam.publish_layer_version(
        LayerName=layer_name,
        Content={"ZipFile": _minimal_zip_bytes()},
        CompatibleRuntimes=["python3.12"],
    )
    version_number = published["Version"]
    ctx.on_cleanup(
        lambda: lam.delete_layer_version(LayerName=layer_name, VersionNumber=version_number)
    )

    # Use the caller's own (real, always-valid) account ID as the grant Principal for every
    # statement. A layer version's resource policy is keyed for uniqueness on StatementId, not
    # Principal, so the same Principal can appear on every statement -- there's no need to
    # fabricate synthetic 12-digit account numbers (which real AWS is free to reject as an
    # invalid Principal) just to pad out statements.
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    # Each statement carries a near-max-length StatementId to reach the 20KB cap in fewer calls.
    long_sid_prefix = "s" * 90
    error_code = error_message = None
    statements_added = 0
    throttle_retries = 0
    # AddLayerVersionPermission mutates the same layer-version policy document on every call, so
    # back-to-back writes at full speed run into real per-resource mutation throttling well
    # before the 20KB size cap is reached. Use a generous wall-clock budget (rather than a small
    # fixed retry count) for throttling backoff so the loop reliably reaches the actual
    # length-exceeded rejection instead of mistaking sustained real throttling for the terminal
    # condition.
    throttle_deadline = time.monotonic() + 600
    i = 0
    while i < 2000:
        try:
            lam.add_layer_version_permission(
                LayerName=layer_name,
                VersionNumber=version_number,
                StatementId=f"{long_sid_prefix}{i}",
                Action="lambda:GetLayerVersion",
                Principal=account_id,
            )
            statements_added += 1
            i += 1
            throttle_retries = 0
            throttle_deadline = time.monotonic() + 600
            # A small fixed pace keeps the call rate under real per-resource mutation
            # throttling.
            time.sleep(0.5)
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "ResourceConflictException":
                # Every StatementId used here is unique to this run (derived from the loop
                # index), so a "statement already exists" conflict for the current index can
                # only mean our own previous attempt at this exact statement already succeeded
                # server-side, even though this client never observed that success (e.g. the
                # response was lost to a transient hiccup). Treat it as progress and move on to
                # the next statement instead of retrying an already-applied write forever.
                statements_added += 1
                i += 1
                throttle_retries = 0
                throttle_deadline = time.monotonic() + 600
                continue
            # Rapid back-to-back writes to the same layer-version policy can also transiently
            # throttle (TooManyRequestsException/ServiceException). That's not the terminal
            # condition we're probing for, so back off and retry the same statement instead of
            # mistaking a transient throttle for the length rejection.
            if (
                code in ("TooManyRequestsException", "ServiceException")
                and time.monotonic() < throttle_deadline
            ):
                throttle_retries += 1
                time.sleep(min(2 ** min(throttle_retries, 6), 30))
                continue
            error_code = code
            error_message = e.response["Error"].get("Message", "")
            break

    assert error_code == "PolicyLengthExceededException", (
        f"expected PolicyLengthExceededException after {statements_added} statements, "
        f"got {error_code!r}"
    )
    # The size AWS reports depends on the ARNs in the policy: assert the text around it.
    assert error_message.startswith("The final policy size (") and error_message.endswith(
        ") is bigger than the limit (20480)."
    ), error_message
    # Without this, a target that rejects every AddLayerVersionPermission call (not just
    # oversized ones) with PolicyLengthExceededException would pass identically.
    assert statements_added > 0, (
        f"expected at least one AddLayerVersionPermission call to succeed before the cap was "
        f"hit, got {statements_added}"
    )

    # Independent read at the destination: the persisted policy must contain exactly the
    # statements that succeeded, proving the rejected call's statement was never applied.
    policy_doc = json.loads(
        lam.get_layer_version_policy(LayerName=layer_name, VersionNumber=version_number)["Policy"]
    )
    persisted = len(policy_doc["Statement"])
    assert persisted == statements_added, (
        f"expected {statements_added} persisted statements after the rejected call, "
        f"got {persisted}"
    )


def _minimal_zip_bytes() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", "def handler(event, context):\n    return {'ok': True}\n")
    return buf.getvalue()


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
