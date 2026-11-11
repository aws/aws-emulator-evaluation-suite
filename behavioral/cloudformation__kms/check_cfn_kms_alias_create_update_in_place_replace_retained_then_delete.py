"""cfn-kms-alias-create-update-in-place-replace-retained-then-delete."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-kms-alias-create-update-in-place-replace-retained-then-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "kms"]

#: A stack operation takes seconds to a few minutes; the bound only stops a hung poll.
_STACK_S = 600.0
_TAGS = [{"Key": "sim2real", "Value": CHECK}]
_REPLACING = (
    "Requested update requires the creation of a new physical resource; hence creating one."
)
_PENDING_DAYS = 7
#: A change or delete reaches every read within seconds; the bound only stops a hung poll.
_PROPAGATE_S = 60.0
_ACCOUNT_ROOT = "arn:${AWS::Partition}:iam::${AWS::AccountId}:root"


@tags(
    "axis:happy-path",
    "cap:c3",
    "concern:data-plane",
    "concern:deploy",
    "concern:representation",
    "dp:api",
    "plane:control",
    "plane:data",
)
def run(ctx) -> None:
    """An AWS::KMS::Alias survives create, in-place retarget, retained replacement and delete.

    ListAliases and Encrypt-by-alias name the templated key; a TargetKeyId change retargets in
    place; an AliasName change under Retain keeps the old alias; deletion is NotFoundException.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-kms-alias.html
    """
    cfn = ctx.client("cloudformation")
    kms = ctx.client("kms")

    stack_name = ctx.unique_name("sim2real-cfnreal-alias-")
    alias_v1 = "alias/" + ctx.unique_name("sim2real-cfnreal-alias-a-")
    alias_v2 = "alias/" + ctx.unique_name("sim2real-cfnreal-alias-b-")

    # The replaced alias outlives the stack, so the check deletes it itself.
    ctx.on_cleanup(lambda: _delete_alias(kms, alias_v1))
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_name))

    # ---- 1. create: CloudFormation view, KMS view, behaviour --------------------------------
    stack_id = cfn.create_stack(
        StackName=stack_name, TemplateBody=_template(alias_v1, "KeyA"), Tags=_TAGS
    )["StackId"]
    created = _settle(ctx, cfn, stack_id)
    assert created["StackStatus"] == "CREATE_COMPLETE", (
        f"create ended {created['StackStatus']!r}: {created.get('StackStatusReason')!r}"
    )
    _assert_tracks(cfn, stack_id, "Alias", alias_v1)
    key_a = _physical(cfn, stack_id, "KeyA")
    key_b = _physical(cfn, stack_id, "KeyB")
    arn_a = kms.describe_key(KeyId=key_a)["KeyMetadata"]["Arn"]
    arn_b = kms.describe_key(KeyId=key_b)["KeyMetadata"]["Arn"]
    partition = arn_a.split(":")[1]
    _assert_alias(ctx, kms, partition, alias_v1, key_a, arn_a)

    # ---- 2. in-place update of the mutable TargetKeyId --------------------------------------
    rows = _update(ctx, cfn, stack_id, "Alias", _template(alias_v1, "KeyB"))
    _assert_updated_in_place(rows, alias_v1)
    _assert_tracks(cfn, stack_id, "Alias", alias_v1)
    _assert_alias(ctx, kms, partition, alias_v1, key_b, arn_b)
    on_a = _poll(
        ctx,
        lambda: kms.list_aliases(KeyId=key_a)["Aliases"],
        lambda aliases: aliases == [],
        cap_s=_PROPAGATE_S,
        what="the retargeted alias to leave key A",
    )
    assert on_a == [], f"the retargeted alias must leave key A, which still lists {on_a!r}"

    # ---- 3. AliasName forces replacement; UpdateReplacePolicy Retain keeps the old one ------
    rows = _update(ctx, cfn, stack_id, "Alias", _template(alias_v2, "KeyB"))
    _assert_replaced_and_retained(rows, alias_v1, alias_v2)
    _assert_tracks(cfn, stack_id, "Alias", alias_v2)
    want = (sorted([alias_v1, alias_v2]), [arn_b, arn_b])
    got = _poll(
        ctx,
        lambda: (
            sorted(a["AliasName"] for a in kms.list_aliases(KeyId=key_b)["Aliases"]),
            [_encrypt_key(kms, alias) for alias in (alias_v1, alias_v2)],
        ),
        lambda v: v == want,
        cap_s=_PROPAGATE_S,
        what="key B to carry the replacement and the retained alias",
    )
    assert got == want, f"key B must carry the replacement and the retained alias, got {got!r}"
    for alias in (alias_v1, alias_v2):
        _encrypts_as(kms, alias, arn_b)

    # ---- 4. DeleteStack: the alias it owns is gone ------------------------------------------
    _delete_and_confirm(ctx, cfn, stack_id)
    alias_arn = f"arn:{partition}:kms:{ctx.region}:{ctx.account}:{alias_v2}"
    want = ("NotFoundException", f"Alias {alias_arn} is not found.")
    _await_error(
        ctx, lambda: kms.describe_key(KeyId=alias_v2), want, "DescribeKey by the deleted alias"
    )
    kept = [a["AliasName"] for a in kms.list_aliases(KeyId=key_b)["Aliases"]]
    assert kept == [alias_v1], f"only the retained alias survives DeleteStack, got {kept!r}"


def _key() -> dict:
    return {
        "Type": "AWS::KMS::Key",
        "Properties": {
            "Description": "reality check alias target",
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
    }


def _template(alias: str, target: str) -> str:
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "KeyA": _key(),
                "KeyB": _key(),
                "Alias": {
                    "Type": "AWS::KMS::Alias",
                    # AliasName is create-only, so a new name replaces the alias.
                    "UpdateReplacePolicy": "Retain",
                    "Properties": {"AliasName": alias, "TargetKeyId": {"Ref": target}},
                },
            },
        }
    )


def _assert_alias(ctx, kms, partition: str, alias: str, key_id: str, key_arn: str) -> None:
    """KMS's view: the alias is the key's only alias; behaviour: Encrypt by alias uses the key.

    A retarget reaches ListAliases and Encrypt within seconds, so both are polled to the key.
    """
    want = [(alias, f"arn:{partition}:kms:{ctx.region}:{ctx.account}:{alias}", key_id)]

    def view():
        aliases = kms.list_aliases(KeyId=key_id)["Aliases"]
        rows = [(a["AliasName"], a["AliasArn"], a["TargetKeyId"]) for a in aliases]
        return rows, _encrypt_key(kms, alias)

    got = _poll(
        ctx,
        view,
        lambda v: v == (want, key_arn),
        cap_s=_PROPAGATE_S,
        what=f"ListAliases for {key_id!r} and Encrypt by {alias!r} to name the key",
    )
    assert got == (want, key_arn), f"ListAliases and Encrypt for {key_id!r}: {got!r}"
    _encrypts_as(kms, alias, key_arn)


def _encrypt_key(kms, alias: str) -> object:
    """The KeyId that Encrypt by alias answers, or the (code, message) it is refused with."""
    try:
        return kms.encrypt(KeyId=alias, Plaintext=b"reality check payload")["KeyId"]
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message") or ""


def _encrypts_as(kms, alias: str, key_arn: str) -> None:
    encrypted = kms.encrypt(KeyId=alias, Plaintext=b"reality check payload")
    assert encrypted["KeyId"] == key_arn, (
        f"Encrypt by {alias!r} must use {key_arn!r}, got {encrypted['KeyId']!r}"
    )
    decrypted = kms.decrypt(CiphertextBlob=encrypted["CiphertextBlob"])
    assert decrypted["Plaintext"] == b"reality check payload", f"Decrypt: {decrypted!r}"


def _delete_alias(kms, alias: str) -> None:
    try:
        kms.delete_alias(AliasName=alias)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


def _await_error(ctx, fn, want: tuple[str, str], what: str) -> None:
    """Poll fn until it is refused, then assert the exact (code, message) want.

    A delete reaches every read within seconds, so a call that still succeeds is retried.
    """
    timeout_s = _budget_s(ctx, _PROPAGATE_S)
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            result = fn()
        except ClientError as exc:
            err = exc.response.get("Error", {})
            got = (err.get("Code"), err.get("Message") or "")
            assert got == want, f"{what}: {got!r}, expected {want!r}"
            return
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"the run budget ended while {what} still succeeded; not graded")
            raise AssertionError(f"{what} still succeeded after {timeout_s:.0f}s: {result!r}")
        time.sleep(2.0)


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


def _error(fn) -> tuple[str, str]:
    """(code, message) of the ClientError fn raises; a call that succeeds fails the check."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message") or ""
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


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


def _assert_replaced_and_retained(rows: list[tuple], old: str, new: str) -> None:
    """The update reported a replacement, completed on the new id and skipped deleting the old."""
    assert _in_order(
        rows,
        [
            ("UPDATE_IN_PROGRESS", _REPLACING, None),
            ("UPDATE_COMPLETE", None, new),
            ("DELETE_SKIPPED", None, old),
        ],
    ), (
        f"the replacement must report creating a new resource, complete as {new!r} and skip "
        f"deleting {old!r} (UpdateReplacePolicy Retain), in that order: {rows!r}"
    )
    deleted = [r for r in rows if r[0] in ("DELETE_IN_PROGRESS", "DELETE_COMPLETE")]
    assert deleted == [], f"UpdateReplacePolicy Retain must delete nothing: {deleted!r}"


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
