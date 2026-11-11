"""cfn-kms-key-create-update-in-place-multi-region-change-refused-then-delete."""

from __future__ import annotations

import json
import re
import time
from datetime import UTC, datetime

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-kms-key-create-update-in-place-multi-region-change-refused-then-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "kms"]

#: A stack operation takes seconds to a few minutes; the bound only stops a hung poll.
_STACK_S = 600.0
#: A key change reaches every KMS read within seconds; the bound stops a hung poll.
_PROPAGATE_S = 120.0
_TAGS = [{"Key": "sim2real", "Value": CHECK}]
_REPLACING = (
    "Requested update requires the creation of a new physical resource; hence creating one."
)
#: CloudFormation's refusal of a MultiRegion change; the RequestToken differs on every update.
_REFUSED = re.compile(
    re.escape(
        'Resource handler returned message: "Invalid request provided: You cannot change the '
        "values of the KeySpec, KeyUsage, Origin, or MultiRegion properties of an AWS::KMS::Key "
        'resource." (RequestToken: '
    )
    + r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
    + re.escape(", HandlerErrorCode: InvalidRequest)")
)
#: The shortest waiting period KMS allows; a deleted key is pending deletion, never gone at once.
_PENDING_DAYS = 7
_ACCOUNT_ROOT = "arn:${AWS::Partition}:iam::${AWS::AccountId}:root"


@tags(
    "axis:happy-path",
    "cap:c3",
    "concern:data-plane",
    "concern:deploy",
    "concern:negative-classes",
    "concern:representation",
    "dp:api",
    "plane:control",
    "plane:data",
)
def run(ctx) -> None:
    """An AWS::KMS::Key survives create and in-place update; a MultiRegion change is refused.

    KMS reads back each template and round-trips data; Description and rotation change in place;
    a MultiRegion change rolls back, leaving the key as it was; deletion leaves it pending.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-kms-key.html
    """
    cfn = ctx.client("cloudformation")
    kms = ctx.client("kms")

    stack_name = ctx.unique_name("sim2real-cfnreal-kms-")
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_name))

    # ---- 1. create: CloudFormation view, KMS view, behaviour --------------------------------
    stack_id = cfn.create_stack(
        StackName=stack_name,
        Tags=_TAGS,
        TemplateBody=_template("first description", rotation=False, multi_region=False),
    )["StackId"]
    created = _settle(ctx, cfn, stack_id)
    assert created["StackStatus"] == "CREATE_COMPLETE", (
        f"create ended {created['StackStatus']!r}: {created.get('StackStatusReason')!r}"
    )
    key_id = _physical(cfn, stack_id, "Key")
    key = kms.describe_key(KeyId=key_id)["KeyMetadata"]
    got = (
        key["KeyId"],
        key["Description"],
        key["KeyState"],
        key["KeySpec"],
        key["KeyUsage"],
        key["MultiRegion"],
    )
    assert got == (
        key_id,
        "first description",
        "Enabled",
        "SYMMETRIC_DEFAULT",
        "ENCRYPT_DECRYPT",
        False,
    ), f"KMS must hold the templated key, got {key!r}"
    rotation = kms.get_key_rotation_status(KeyId=key_id)["KeyRotationEnabled"]
    assert rotation is False, f"rotation is off as templated, got {rotation!r}"
    _round_trip(kms, key_id, key["Arn"])

    # ---- 2. in-place update of the mutable Description and EnableKeyRotation ----------------
    body = _template("second description", rotation=True, multi_region=False)
    _assert_updated_in_place(_update(ctx, cfn, stack_id, "Key", body), key_id)
    _assert_tracks(cfn, stack_id, "Key", key_id)
    # KMS reads are eventually consistent: poll until the update shows, then grade it exactly.
    updated = _poll(
        ctx,
        lambda: kms.describe_key(KeyId=key_id)["KeyMetadata"],
        lambda k: k["Description"] == "second description",
        cap_s=_PROPAGATE_S,
        what=f"key {key_id} Description updated",
    )
    assert updated["CreationDate"] == key["CreationDate"], "an in-place update keeps the key"
    rotation = _poll(
        ctx,
        lambda: kms.get_key_rotation_status(KeyId=key_id)["KeyRotationEnabled"],
        lambda enabled: enabled is True,
        cap_s=_PROPAGATE_S,
        what=f"key {key_id} rotation enabled",
    )
    assert rotation is True, f"the in-place update must enable rotation, got {rotation!r}"
    _round_trip(kms, key_id, key["Arn"])

    # ---- 3. MultiRegion cannot change on an existing key: the update is refused, rolled back --
    body = _template("second description", rotation=True, multi_region=True)
    stack, failed = _update_refused(ctx, cfn, stack_id, body)
    assert stack["StackStatus"] == "UPDATE_ROLLBACK_COMPLETE", (
        f"a refused update rolls back, got {stack['StackStatus']!r}; failed rows {failed!r}"
    )
    assert [(lid, status) for lid, status, _ in failed] == [("Key", "UPDATE_FAILED")], (
        f"only the Key fails its update, got {failed!r}"
    )
    assert _REFUSED.fullmatch(failed[0][2] or ""), (
        f"the Key's UPDATE_FAILED reason must be the MultiRegion refusal, got {failed[0][2]!r}"
    )
    _assert_tracks(cfn, stack_id, "Key", key_id)
    kept = kms.describe_key(KeyId=key_id)["KeyMetadata"]
    got = (kept["KeyId"], kept["Description"], kept["KeyState"], kept["MultiRegion"])
    assert got == (key_id, "second description", "Enabled", False), (
        f"the refused update must leave the key enabled and single-Region, got {kept!r}"
    )
    _round_trip(kms, key_id, key["Arn"])

    # ---- 4. DeleteStack: the key it owns is pending deletion and refuses use ----------------
    _delete_and_confirm(ctx, cfn, stack_id)
    want = ("KMSInvalidStateException", f"{key['Arn']} is pending deletion.")
    gone, got = _poll(
        ctx,
        lambda: _deletion_view(kms, key_id),
        lambda view: view[0]["KeyState"] == "PendingDeletion" and view[1] is not None,
        cap_s=_PROPAGATE_S,
        what=f"key {key_id} pending deletion and refusing Encrypt",
    )
    days = (gone["DeletionDate"] - datetime.now(UTC)).total_seconds() / 86400
    assert _PENDING_DAYS - 1 < days <= _PENDING_DAYS + 1, (
        f"the templated PendingWindowInDays {_PENDING_DAYS} applies, got {gone!r}"
    )
    assert got == want, f"Encrypt with the deleted key: {got!r}, expected {want!r}"


def _template(description: str, *, rotation: bool, multi_region: bool) -> str:
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "Key": {
                    "Type": "AWS::KMS::Key",
                    "Properties": {
                        "Description": description,
                        "EnableKeyRotation": rotation,
                        "MultiRegion": multi_region,
                        "PendingWindowInDays": _PENDING_DAYS,
                        "KeyPolicy": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Sid": "AccountAdmin",
                                    "Effect": "Allow",
                                    "Principal": {"AWS": {"Fn::Sub": _ACCOUNT_ROOT}},
                                    "Action": "kms:*",
                                    "Resource": "*",
                                }
                            ],
                        },
                    },
                },
            },
        }
    )


def _deletion_view(kms, key_id: str) -> tuple[dict, tuple[str, str] | None]:
    """The key's metadata and Encrypt's (code, message) refusal, or None while Encrypt succeeds."""
    metadata = kms.describe_key(KeyId=key_id)["KeyMetadata"]
    try:
        kms.encrypt(KeyId=key_id, Plaintext=b"after delete")
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return metadata, (err.get("Code"), err.get("Message") or "")
    return metadata, None


def _round_trip(kms, key_id: str, key_arn: str) -> None:
    """Behaviour: the key encrypts, and decrypts its own ciphertext back to the plaintext."""
    plaintext = b"reality check payload"
    encrypted = kms.encrypt(KeyId=key_id, Plaintext=plaintext)
    assert encrypted["KeyId"] == key_arn, f"Encrypt must name the key {key_arn!r}: {encrypted!r}"
    decrypted = kms.decrypt(CiphertextBlob=encrypted["CiphertextBlob"])
    assert (decrypted["KeyId"], decrypted["Plaintext"]) == (key_arn, plaintext), (
        f"Decrypt must return the plaintext under {key_arn!r}, got {decrypted!r}"
    )


def _update_refused(ctx, cfn, stack_id: str, body: str) -> tuple[dict, list[tuple]]:
    """UpdateStack to body; the settled stack and the update's failed rows, oldest first.

    A row is (LogicalResourceId, ResourceStatus, ResourceStatusReason).
    """
    before = len(_events(cfn, stack_id))
    cfn.update_stack(StackName=stack_id, TemplateBody=body)
    stack = _settle(ctx, cfn, stack_id)
    failed = [
        (e["LogicalResourceId"], e["ResourceStatus"], e.get("ResourceStatusReason"))
        for e in _events(cfn, stack_id)[before:]
        if e["ResourceStatus"].endswith("_FAILED")
    ]
    return stack, failed


# ===== stack helpers =====


def _budget_s(ctx, cap_s: float) -> float:
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx) -> bool:
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll(ctx, probe, done, *, cap_s: float, what: str, interval_s: float = 2.0):
    """Call probe() until done(result) holds and return it; ctx=None (teardown) is not budgeted."""
    timeout_s = cap_s if ctx is None else _budget_s(ctx, cap_s)
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if done(last):
            return last
        if time.monotonic() >= deadline:
            if ctx is not None and _budget_spent(ctx):
                raise TimeoutError(f"the run budget ended while waiting for {what}; not graded")
            raise AssertionError(f"{what} not reached within {timeout_s:.0f}s; last {last!r}")
        time.sleep(interval_s)


def _stack(cfn, stack_id: str) -> dict:
    return cfn.describe_stacks(StackName=stack_id)["Stacks"][0]


def _settle(ctx, cfn, stack_id: str) -> dict:
    """The stack once no operation (cleanup phase included) is in progress on it."""
    return _poll(
        ctx,
        lambda: _stack(cfn, stack_id),
        lambda s: not s["StackStatus"].endswith("_IN_PROGRESS"),
        cap_s=_STACK_S,
        what=f"stack {stack_id} settled",
    )


def _physical(cfn, stack_id: str, logical_id: str) -> str:
    return cfn.describe_stack_resource(StackName=stack_id, LogicalResourceId=logical_id)[
        "StackResourceDetail"
    ]["PhysicalResourceId"]


def _assert_tracks(cfn, stack_id: str, logical_id: str, expected: str) -> None:
    """CloudFormation's view: the stack resource carries the expected PhysicalResourceId."""
    got = _physical(cfn, stack_id, logical_id)
    assert got == expected, f"the stack must track {logical_id} as {expected!r}, got {got!r}"


def _events(cfn, stack_id: str) -> list[dict]:
    """Every stack event, oldest first (the API pages newest first)."""
    out: list[dict] = []
    for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack_id):
        out.extend(page["StackEvents"])
    return out[::-1]


def _update(ctx, cfn, stack_id: str, logical_id: str, body: str, **kw) -> list[tuple]:
    """UpdateStack to body, assert UPDATE_COMPLETE and return the update's rows for logical_id.

    A row is (ResourceStatus, ResourceStatusReason, PhysicalResourceId), oldest first.
    """
    before = len(_events(cfn, stack_id))
    cfn.update_stack(StackName=stack_id, TemplateBody=body, **kw)
    stack = _settle(ctx, cfn, stack_id)
    events = _events(cfn, stack_id)[before:]
    failed = [
        (e["LogicalResourceId"], e.get("ResourceStatusReason"))
        for e in events
        if e["ResourceStatus"].endswith("_FAILED")
    ]
    assert stack["StackStatus"] == "UPDATE_COMPLETE", (
        f"update ended {stack['StackStatus']!r}: {stack.get('StackStatusReason')!r}; {failed!r}"
    )
    return [
        (e["ResourceStatus"], e.get("ResourceStatusReason"), e.get("PhysicalResourceId"))
        for e in events
        if e["LogicalResourceId"] == logical_id
    ]


def _in_order(rows: list[tuple], wanted: list[tuple]) -> bool:
    """Whether every wanted row occurs in rows in that order; a None field matches any value."""
    remaining = iter(rows)
    return all(
        any(all(w is None or w == v for w, v in zip(want, row, strict=True)) for row in remaining)
        for want in wanted
    )


def _assert_updated_in_place(rows: list[tuple], physical: str) -> None:
    """The update completed on the same physical id and reported no replacement or delete."""
    assert _in_order(
        rows, [("UPDATE_IN_PROGRESS", None, None), ("UPDATE_COMPLETE", None, physical)]
    ), f"an in-place update must progress and complete on {physical!r}: {rows!r}"
    replacing = [r for r in rows if r[1] == _REPLACING or r[0].startswith("DELETE_")]
    assert replacing == [], f"an in-place update must not replace anything: {replacing!r}"


def _delete_and_confirm(ctx, cfn, stack_id: str) -> None:
    """DeleteStack by StackId and assert it reaches DELETE_COMPLETE."""
    cfn.delete_stack(StackName=stack_id)
    final = _poll(
        ctx,
        lambda: _stack(cfn, stack_id)["StackStatus"],
        lambda s: not s.endswith("_IN_PROGRESS"),
        cap_s=_STACK_S,
        what=f"stack {stack_id} deleted",
    )
    assert final == "DELETE_COMPLETE", (
        f"DeleteStack ended {final!r}: {_stack(cfn, stack_id).get('StackStatusReason')!r}"
    )


def _delete_stack(cfn, stack_name: str) -> None:
    """Teardown: delete the stack by its StackId and wait; DELETE_FAILED or a timeout raises."""
    try:
        stack_id = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackId"]
    except ClientError as exc:
        if exc.response["Error"].get("Message") == f"Stack with id {stack_name} does not exist":
            return
        raise
    status = _poll(
        None,
        lambda: _stack(cfn, stack_id)["StackStatus"],
        lambda s: not s.endswith("_IN_PROGRESS"),
        cap_s=_STACK_S,
        what=f"stack {stack_id} settled before teardown",
    )
    if status == "DELETE_COMPLETE":
        return
    cfn.delete_stack(StackName=stack_id)
    final = _poll(
        None,
        lambda: _stack(cfn, stack_id)["StackStatus"],
        lambda s: s in ("DELETE_COMPLETE", "DELETE_FAILED"),
        cap_s=_STACK_S,
        what=f"stack {stack_id} deleted",
    )
    if final != "DELETE_COMPLETE":
        raise AssertionError(
            f"stack {stack_id} ended {final}: {_stack(cfn, stack_id).get('StackStatusReason')!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
