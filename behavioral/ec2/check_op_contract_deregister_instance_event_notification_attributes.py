"""op-contract-deregister-instance-event-notification-attributes."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "op-contract-deregister-instance-event-notification-attributes"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:ec2-instance-event-notification-attributes")
def run(ctx) -> None:
    """DeregisterInstanceEventNotificationAttributes removes tag keys from the
    account-level scheduled-event-notification allow list; DryRun still
    performs authorization checks without mutating state."""
    ec2 = ctx.client("ec2")

    tag_key = ctx.unique_name("sim2real-behav-notify-tag-")

    baseline = ec2.describe_instance_event_notification_attributes()["InstanceTagAttribute"]
    baseline_keys = set(baseline.get("InstanceTagKeys", []))
    assert tag_key not in baseline_keys, "unique tag key unexpectedly already registered"

    def _cleanup():
        # The success path below already deregisters tag_key; deregistering
        # an already-absent tag key raises
        # InvalidNotificationAttributeInstanceTagNotFound, so make this
        # teardown idempotent rather than letting that (expected) error
        # escape from cleanup.
        from botocore.exceptions import ClientError

        try:
            ec2.deregister_instance_event_notification_attributes(
                InstanceTagAttribute={"InstanceTagKeys": [tag_key]}
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidNotificationAttributeInstanceTagNotFound":
                raise

    ctx.on_cleanup(_cleanup)

    reg = ec2.register_instance_event_notification_attributes(
        InstanceTagAttribute={"InstanceTagKeys": [tag_key]}
    )["InstanceTagAttribute"]
    assert tag_key in reg.get("InstanceTagKeys", []), "tag key was not registered"

    described = ec2.describe_instance_event_notification_attributes()["InstanceTagAttribute"]
    assert tag_key in described.get("InstanceTagKeys", []), "registration not reflected in describe"

    # error boundary: DryRun performs the permission/validation check but never mutates.
    # Even though describe_instance_event_notification_attributes already
    # reflects the registration, the backend that validates
    # DeregisterInstanceEventNotificationAttributes' InstanceTagKeys can lag
    # briefly behind that view and reject the (very much registered) tag key
    # as not-found; retry within a bounded window until it settles and the
    # real DryRun outcome is observed.
    code, message = _poll_until(
        lambda: _error(
            lambda: ec2.deregister_instance_event_notification_attributes(
                DryRun=True, InstanceTagAttribute={"InstanceTagKeys": [tag_key]}
            )
        ),
        lambda err: err[0] != "InvalidNotificationAttributeInstanceTagNotFound",
        timeout_s=30,
        interval_s=2,
    )
    assert code == "DryRunOperation", f"expected DryRunOperation, got {code}"
    assert message == "Request would have succeeded, but DryRun flag is set.", (
        f"unexpected DryRunOperation message: {message!r}"
    )

    still_present = ec2.describe_instance_event_notification_attributes()["InstanceTagAttribute"]
    assert tag_key in still_present.get("InstanceTagKeys", []), "DryRun must not mutate state"

    # success path: real deregistration removes the tag key. The mutation
    # response can lag behind the actual removal by a beat, so retry the
    # (idempotent) call within a bounded window until it reports the key gone.
    # The backend that validates this call's InstanceTagKeys can also briefly
    # consider a still-registered key as InvalidNotificationAttributeInstanceTagNotFound
    # (the same lag observed above for DryRun); from this call's own point of
    # view that means the key is already gone, so treat that specific error as
    # success rather than letting it escape as an unexpected ClientError.
    def _dereg_once():
        from botocore.exceptions import ClientError

        try:
            return ec2.deregister_instance_event_notification_attributes(
                InstanceTagAttribute={"InstanceTagKeys": [tag_key]}
            )["InstanceTagAttribute"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "InvalidNotificationAttributeInstanceTagNotFound":
                return {"InstanceTagKeys": []}
            raise

    dereg = _poll_until(
        _dereg_once,
        lambda attr: tag_key not in attr.get("InstanceTagKeys", []),
        timeout_s=30,
        interval_s=2,
    )
    assert tag_key not in dereg.get("InstanceTagKeys", []), "tag key still present after deregistration"

    final = _poll_until(
        lambda: ec2.describe_instance_event_notification_attributes()["InstanceTagAttribute"],
        lambda attr: tag_key not in attr.get("InstanceTagKeys", []),
        timeout_s=30,
        interval_s=2,
    )
    assert tag_key not in final.get("InstanceTagKeys", []), "deregistration not reflected in describe"

    # deletes prove gone AND unusable: the same call that already worked now
    # rejects the already-absent tag key with the specific not-found code.
    from botocore.exceptions import ClientError

    try:
        ec2.deregister_instance_event_notification_attributes(
            InstanceTagAttribute={"InstanceTagKeys": [tag_key]}
        )
        raise AssertionError(
            "expected InvalidNotificationAttributeInstanceTagNotFound deregistering an "
            "already-removed tag key, got success"
        )
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        assert code == "InvalidNotificationAttributeInstanceTagNotFound", (
            f"expected InvalidNotificationAttributeInstanceTagNotFound, got {code}"
        )
        # AWS returns this code with no Message element at all.
        message = exc.response["Error"].get("Message")
        assert message is None, f"expected no Message with this code, got {message!r}"


def _error(fn):
    """Call fn(); return (code, message) of its ClientError. A success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded: {result!r}")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out after {timeout_s}s waiting for predicate; last value was {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
