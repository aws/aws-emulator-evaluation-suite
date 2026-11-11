"""tag-resource-list-and-untag-roundtrip."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-resource-list-and-untag-roundtrip"
GROUP = "state"
SERVICES = ["bedrock-agentcore-control"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListTagsForResource returns a gateway's creation tags, TagResource adds one and UntagResource removes it
    leaving the rest; after DeleteGateway, ListTagsForResource and TagResource answer NotFoundException "Resource was
    not found"."""
    control = ctx.client("bedrock-agentcore-control")
    role_arn = _create_gateway_role(ctx)

    gw = _retry_until_role_usable(
        lambda: control.create_gateway(
            name=ctx.unique_name("sim2real-gw-tags-"),
            roleArn=role_arn,
            authorizerType="AWS_IAM",
            tags={"env": "sim2real-test", "purpose": "tag-roundtrip"},
        )
    )
    gateway_id = gw["gatewayId"]
    gateway_arn = gw["gatewayArn"]
    ctx.on_cleanup(lambda: _ac_delete_gateway(control, gateway_id))

    tags = control.list_tags_for_resource(resourceArn=gateway_arn)["tags"]
    expected = {"env": "sim2real-test", "purpose": "tag-roundtrip"}
    assert tags == expected, f"expected tags at creation {expected!r}, got {tags!r}"

    control.tag_resource(resourceArn=gateway_arn, tags={"stage": "extra"})
    tags2 = control.list_tags_for_resource(resourceArn=gateway_arn)["tags"]
    expected2 = {"env": "sim2real-test", "purpose": "tag-roundtrip", "stage": "extra"}
    assert tags2 == expected2, f"expected tags after TagResource {expected2!r}, got {tags2!r}"

    control.untag_resource(resourceArn=gateway_arn, tagKeys=["stage"])
    tags3 = control.list_tags_for_resource(resourceArn=gateway_arn)["tags"]
    assert tags3 == expected, f"expected tags after UntagResource {expected!r}, got {tags3!r}"

    ready_state = _poll_until(
        lambda: control.get_gateway(gatewayIdentifier=gateway_id),
        lambda r: r["status"] != "CREATING",
        timeout_s=120.0,
    )
    assert ready_state["status"] == "READY", f"unexpected terminal status {ready_state['status']!r}"

    control.delete_gateway(gatewayIdentifier=gateway_id)
    code, message = _error(
        lambda: control.list_tags_for_resource(resourceArn=gateway_arn),
        until_code="NotFoundException",
        timeout_s=90.0,
    )
    assert code == "NotFoundException", (
        f"expected NotFoundException reading tags after DeleteGateway, got {code!r}"
    )
    expected_message = "Resource was not found"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    tag_after_delete_code, tag_after_delete_message = _error(
        lambda: control.tag_resource(resourceArn=gateway_arn, tags={"stage": "extra"})
    )
    assert tag_after_delete_code == "NotFoundException", (
        f"expected NotFoundException tagging a deleted gateway, got {tag_after_delete_code!r}"
    )
    expected_message = "Resource was not found"
    assert tag_after_delete_message == expected_message, (
        f"expected message {expected_message!r}, got {tag_after_delete_message!r}"
    )


# AgentCore refuses a delete while the resource is CREATING/UPDATING or still has dependents
# (ValidationException/ConflictException), and an accepted delete completes asynchronously, so a
# teardown waits out transitional statuses and then for the resource to be gone.
_AC_TRANSITIONAL = ("CREATING", "UPDATING", "DELETING", "SYNCHRONIZING")


def _ac_delete_and_wait(get_status, delete, *, what, timeout_s=600.0, interval_s=5.0):
    """Delete once out of a transitional status, then wait for ResourceNotFound; raise on timeout."""
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        try:
            last = get_status()
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        if last == "DELETED":
            return
        if last not in _AC_TRANSITIONAL:
            try:
                delete()
            except ClientError as exc:
                code = exc.response["Error"]["Code"]
                if code == "ResourceNotFoundException":
                    return
                if code not in ("ConflictException", "ValidationException"):
                    raise
                last = f"{last}; delete refused: {exc}"
        if time.monotonic() >= deadline:
            raise AssertionError(f"teardown: {what} still present after {timeout_s}s ({last})")
        time.sleep(interval_s)


def _ac_delete_gateway(control, gateway_id):
    """Delete every target first (DeleteGateway is refused while one exists), then the gateway."""
    try:
        pages = control.get_paginator("list_gateway_targets").paginate(gatewayIdentifier=gateway_id)
        target_ids = [t["targetId"] for page in pages for t in page.get("items", [])]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFoundException":
            return
        raise
    for target_id in target_ids:
        _ac_delete_and_wait(
            lambda: control.get_gateway_target(gatewayIdentifier=gateway_id, targetId=target_id)["status"],
            lambda: control.delete_gateway_target(gatewayIdentifier=gateway_id, targetId=target_id),
            what=f"gateway target {target_id}",
        )
    _ac_delete_and_wait(
        lambda: control.get_gateway(gatewayIdentifier=gateway_id)["status"],
        lambda: control.delete_gateway(gatewayIdentifier=gateway_id),
        what=f"gateway {gateway_id}",
    )


def _create_gateway_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-agentcore-gw-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "bedrock-agentcore.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    resp = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy)
    )
    role_arn = resp["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return role_arn


def _retry_until_role_usable(fn, timeout_s=90.0, interval_s=5.0):
    # IAM role trust policies are eventually consistent; a freshly created
    # role may not yet be assumable by bedrock-agentcore.amazonaws.com when
    # the create call is first made. Poll the real create call itself until
    # it stops being rejected for role-related reasons.
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in ("AccessDeniedException", "ValidationException"):
                last_exc = exc
                time.sleep(interval_s)
                continue
            raise
    raise last_exc


def _error(fn, *, until_code=None, timeout_s=0.0, interval_s=3.0):
    """Return (code, message) of the ClientError fn() raises. With until_code, retry while fn()
    succeeds or raises another code, for up to timeout_s. A call that never fails raises."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            result = fn()
        except ClientError as err:
            error = err.response["Error"]
            if until_code is None or error["Code"] == until_code or time.monotonic() >= deadline:
                return error["Code"], error.get("Message", "")
        else:
            if time.monotonic() >= deadline:
                raise AssertionError(
                    f"expected a ClientError, but the call succeeded and returned {result!r}"
                )
        time.sleep(interval_s)


def _poll_until(probe, predicate, timeout_s=90.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
