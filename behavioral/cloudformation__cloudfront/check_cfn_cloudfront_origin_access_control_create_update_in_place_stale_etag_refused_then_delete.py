"""cfn-cloudfront-origin-access-control-create-update-in-place-stale-etag-refused-then-delete."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-cloudfront-origin-access-control-create-update-in-place-stale-etag-refused-then-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "cloudfront"]

#: A stack operation takes seconds to a few minutes; the bound only stops a hung poll.
_STACK_S = 600.0
#: A deleted origin access control stops resolving within seconds; the bound stops a hung poll.
_GONE_S = 60.0
_TAGS = [{"Key": "sim2real", "Value": CHECK}]
_REPLACING = (
    "Requested update requires the creation of a new physical resource; hence creating one."
)
#: GetOriginAccessControl of an origin access control that does not exist.
_NOT_FOUND = (
    "NoSuchOriginAccessControl",
    "The specified origin access control does not exist.",
)
#: A write carrying an ETag the resource has moved past.
_STALE_ETAG = (
    "PreconditionFailed",
    "The request failed because it didn't meet the preconditions in one or more request-header "
    "fields.",
)


def _config(name: str, description: str, signing_behavior: str) -> dict:
    return {
        "Name": name,
        "Description": description,
        "OriginAccessControlOriginType": "s3",
        "SigningBehavior": signing_behavior,
        "SigningProtocol": "sigv4",
    }


@tags(
    "axis:happy-path",
    "cap:c3",
    "concern:deploy",
    "concern:representation",
    "plane:control",
)
def run(ctx) -> None:
    """An AWS::CloudFront::OriginAccessControl survives create, in-place update and delete.

    CloudFront reads back the templated config; an update keeps the Id under a new ETag, and a
    delete with the superseded ETag is refused. No property forces a replacement.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-cloudfront-originaccesscontrol.html
    """
    cfn = ctx.client("cloudformation")
    cloudfront = ctx.client("cloudfront")

    stack_name = ctx.unique_name("sim2real-cfnreal-oac-stack-")
    name = ctx.unique_name("sim2real-cfnreal-oac-")
    config_v1 = _config(name, "sim2real origin access control, first", "always")
    config_v2 = _config(name, "sim2real origin access control, updated", "no-override")

    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_name))

    # ---- 1. create: CloudFormation view, CloudFront view ------------------------------------
    stack_id = cfn.create_stack(
        StackName=stack_name, TemplateBody=_template(config_v1), Tags=_TAGS
    )["StackId"]
    created = _settle(ctx, cfn, stack_id)
    assert created["StackStatus"] == "CREATE_COMPLETE", (
        f"create ended {created['StackStatus']!r}: {created.get('StackStatusReason')!r}"
    )
    oac_id = _physical(cfn, stack_id, "Oac")
    outputs = _outputs(cfn, stack_id)
    assert outputs == {"Id": oac_id}, f"GetAtt Id must be the PhysicalResourceId: {outputs!r}"
    etag_v1 = _assert_oac(cloudfront, oac_id, config_v1)

    # ---- 2. in-place update of the mutable OriginAccessControlConfig ------------------------
    rows = _update(ctx, cfn, stack_id, "Oac", _template(config_v2))
    _assert_updated_in_place(rows, oac_id)
    _assert_tracks(cfn, stack_id, "Oac", oac_id)
    etag_v2 = _assert_oac(cloudfront, oac_id, config_v2)
    assert etag_v2 != etag_v1, f"an update must give the config a new ETag, still {etag_v1!r}"

    # ---- behaviour: the superseded ETag no longer authorizes a write ------------------------
    got = _error(lambda: cloudfront.delete_origin_access_control(Id=oac_id, IfMatch=etag_v1))
    assert got == _STALE_ETAG, f"a delete with the superseded ETag: {got!r}, not {_STALE_ETAG!r}"
    assert _assert_oac(cloudfront, oac_id, config_v2) == etag_v2, (
        "the refused delete must leave the origin access control and its ETag unchanged"
    )

    # ---- 3. DeleteStack: the origin access control is gone ----------------------------------
    _delete_and_confirm(ctx, cfn, stack_id)
    got = _poll(
        ctx,
        lambda: _refusal(lambda: cloudfront.get_origin_access_control(Id=oac_id)),
        lambda e: e[0] != "<exists>",
        cap_s=_GONE_S,
        what=f"GetOriginAccessControl of {oac_id!r} refused after DeleteStack",
    )
    assert got == _NOT_FOUND, f"GetOriginAccessControl after DeleteStack: {got!r}"


def _template(config: dict) -> str:
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "Oac": {
                    "Type": "AWS::CloudFront::OriginAccessControl",
                    "Properties": {"OriginAccessControlConfig": config},
                },
            },
            "Outputs": {"Id": {"Value": {"Fn::GetAtt": ["Oac", "Id"]}}},
        }
    )


def _outputs(cfn, stack_id: str) -> dict:
    stack = _stack(cfn, stack_id)
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}


def _assert_oac(cloudfront, oac_id: str, config: dict) -> str:
    """CloudFront's view: the origin access control holds exactly config; return its ETag."""
    got = cloudfront.get_origin_access_control(Id=oac_id)
    oac = got["OriginAccessControl"]
    assert oac["Id"] == oac_id, f"GetOriginAccessControl must answer for {oac_id!r}: {oac!r}"
    assert oac["OriginAccessControlConfig"] == config, (
        f"origin access control {oac_id!r} must hold {config!r}, got {oac!r}"
    )
    return got["ETag"]


def _refusal(fn) -> tuple[str, str]:
    """(code, message) of the ClientError fn raises, or an <exists> pair while it succeeds."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message") or ""
    return "<exists>", "the call still succeeds"


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
