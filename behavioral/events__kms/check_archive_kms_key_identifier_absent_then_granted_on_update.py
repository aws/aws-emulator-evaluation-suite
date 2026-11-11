"""archive-kms-key-identifier-absent-then-granted-on-update."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "archive-kms-key-identifier-absent-then-granted-on-update"
GROUP = "archive"
SERVICES = ["events", "kms"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateArchive without a key leaves KmsKeyIdentifier unset; UpdateArchive with a key
    EventBridge may use sets and describes it, and a key it may not use is refused.
    """
    events = ctx.client("events")
    kms = ctx.client("kms")

    bus = ctx.unique_name("sim2real-behav-bus-")
    bus_arn = events.create_event_bus(Name=bus, Tags=[{"Key": "sim2real", "Value": CHECK}])["EventBusArn"]
    ctx.on_cleanup(lambda: events.delete_event_bus(Name=bus))

    archive = ctx.unique_name("sim2real-behav-archive-")
    events.create_archive(ArchiveName=archive, EventSourceArn=bus_arn)
    ctx.on_cleanup(lambda: events.delete_archive(ArchiveName=archive))
    _await_state(events, archive, "ENABLED")
    desc = events.describe_archive(ArchiveName=archive)
    assert "KmsKeyIdentifier" not in desc, (
        f"a key-less archive described KmsKeyIdentifier={desc.get('KmsKeyIdentifier')!r}"
    )

    granted_key = _create_key(ctx, kms, grant_events=True)
    ungranted_key = _create_key(ctx, kms, grant_events=False)

    # --- UpdateArchive with a key EventBridge may not use is refused; the archive stays keyless. ---
    _ungranted_key_denied = (
        "ValidationException",
        "KMS returned an access denied exception when calling the GenerateDataKey API for the "
        f"key with ARN {ungranted_key}. Please ensure that events.amazonaws.com has permissions "
        "to access GenerateDataKey.",
    )
    code, message = _error(lambda: events.update_archive(ArchiveName=archive, KmsKeyIdentifier=ungranted_key))
    assert (code, message) == _ungranted_key_denied, f"UpdateArchive with an ungranted key gave {code!r}: {message!r}"
    _await_state(events, archive, "ENABLED")
    desc = events.describe_archive(ArchiveName=archive)
    assert "KmsKeyIdentifier" not in desc, (
        f"the refused update must leave the archive keyless, got {desc.get('KmsKeyIdentifier')!r}"
    )

    # --- UpdateArchive with a key EventBridge may use succeeds, and DescribeArchive reports it. ---
    events.update_archive(ArchiveName=archive, KmsKeyIdentifier=granted_key)
    _await_state(events, archive, "ENABLED")
    desc = events.describe_archive(ArchiveName=archive)
    assert desc.get("KmsKeyIdentifier") == granted_key, (
        f"DescribeArchive reported key {desc.get('KmsKeyIdentifier')!r}, expected {granted_key!r}"
    )


def _create_key(ctx, kms, *, grant_events: bool) -> str:
    statements = [{
        "Sid": "AccountAdmin",
        "Effect": "Allow",
        "Principal": {"AWS": f"arn:aws:iam::{ctx.account}:root"},
        "Action": "kms:*",
        "Resource": "*",
    }]
    if grant_events:
        statements.append({
            "Sid": "AllowEventBridgeArchive",
            "Effect": "Allow",
            "Principal": {"Service": "events.amazonaws.com"},
            "Action": ["kms:DescribeKey", "kms:GenerateDataKey", "kms:Decrypt", "kms:ReEncrypt*"],
            "Resource": "*",
        })
    meta = kms.create_key(
        Description=f"sim2real {CHECK}",
        Policy=json.dumps({"Version": "2012-10-17", "Statement": statements}),
        Tags=[{"TagKey": "sim2real", "TagValue": CHECK}],
    )["KeyMetadata"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=meta["KeyId"], PendingWindowInDays=7))
    return meta["Arn"]


def _await_state(events, archive: str, state: str, *, timeout_s: float = 60.0) -> None:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = events.describe_archive(ArchiveName=archive)
        if last["State"] == state:
            return
        if last["State"] == "CREATE_FAILED":
            raise AssertionError(f"archive {archive} reached CREATE_FAILED: {last.get('StateReason')!r}")
        time.sleep(2)
    raise AssertionError(f"archive {archive} never reached {state} in {timeout_s}s: {last!r}")


def _error(fn) -> tuple[str, str]:
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
