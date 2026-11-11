"""delete-sink-with-attached-link-conflict-rejected."""
from __future__ import annotations

import json
import time
import uuid

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "delete-sink-with-attached-link-conflict-rejected"
GROUP = "overly-permissive"
SERVICES = ["oam"]
_NOT_FOUND = "Resource not found."


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:oam-sink")
def run(ctx) -> None:
    """DeleteSink on a link-shaped ARN fails with AccessDeniedException and the exact message; after
    deleting a real sink with a policy, GetSink, GetSinkPolicy and a second DeleteSink fail with
    ResourceNotFoundException and the exact message."""
    oam = ctx.client("oam")
    account_id = _own_account_id(ctx)
    region = ctx.region

    # a syntactically well-formed LINK arn (never created) passed to DeleteSink must be rejected,
    # not accepted as if any oam-shaped ARN were an acceptable sink identifier.
    link_shaped_arn = f"arn:aws:oam:{region}:{account_id}:link/{uuid.uuid4()}"
    code, code_message = _error(lambda: oam.delete_sink(Identifier=link_shaped_arn))
    assert code == "AccessDeniedException", f"got {code!r}"
    assert code_message == _explicit_deny_message(ctx, "DeleteSink", link_shaped_arn), f"got message {code_message!r}"

    # real sink + policy lifecycle: deleting the sink removes the policy with it.
    sink_name = ctx.unique_name("sim2real-oam-sink-")
    sink = _create_sink_retrying(oam, sink_name, tags={"sim2real-check": CHECK})
    sink_arn = sink["Arn"]
    ctx.on_cleanup(lambda: _delete_sink_ignore_missing(oam, sink_arn))
    oam.put_sink_policy(SinkIdentifier=sink_arn, Policy=_own_account_sink_policy(account_id))
    got_policy = oam.get_sink_policy(SinkIdentifier=sink_arn)
    assert got_policy["SinkArn"] == sink_arn, f"expected SinkArn={sink_arn!r}, got {got_policy['SinkArn']!r}"

    oam.delete_sink(Identifier=sink_arn)

    gone_code, gone_code_message = _error(lambda: oam.get_sink(Identifier=sink_arn))
    assert gone_code == "ResourceNotFoundException", f"got {gone_code!r}"
    assert gone_code_message == _NOT_FOUND, f"got message {gone_code_message!r}"
    policy_gone_code, policy_gone_code_message = _error(lambda: oam.get_sink_policy(SinkIdentifier=sink_arn))
    assert policy_gone_code == "ResourceNotFoundException", f"got {policy_gone_code!r}"
    assert policy_gone_code_message == _NOT_FOUND, f"got message {policy_gone_code_message!r}"

    # a second DeleteSink on the same now-gone sink is rejected, not a silent no-op success.
    second_delete_code, second_delete_code_message = _error(lambda: oam.delete_sink(Identifier=sink_arn))
    assert second_delete_code == "ResourceNotFoundException", f"got {second_delete_code!r}"
    assert second_delete_code_message == _NOT_FOUND, f"got message {second_delete_code_message!r}"


def _explicit_deny_message(ctx, action, resource):
    caller = ctx.client("sts").get_caller_identity()["Arn"]
    return (
        f"User: {caller} is not authorized to perform: oam:{action} on resource: {resource} "
        "with an explicit deny in a resource-based policy"
    )


def _error(fn):
    """Call fn(), which must fail; return its botocore error (code, message). An unexpected
    SUCCESS raises, so a target that accepts what AWS refuses is never read as a mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response["Error"]
        return error["Code"], error.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _own_account_id(ctx):
    return ctx.client("sts").get_caller_identity()["Account"]


def _own_account_sink_policy(account_id):
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Action": ["oam:CreateLink", "oam:UpdateLink"],
                    "Effect": "Allow",
                    "Resource": "*",
                    "Principal": {"AWS": [account_id]},
                }
            ],
        }
    )


def _create_sink_retrying(oam, name, timeout_s=90.0, interval_s=3.0, tags=None):
    deadline = time.monotonic() + timeout_s
    last_exc = None
    kwargs = {"Name": name}
    if tags:
        kwargs["Tags"] = tags
    while time.monotonic() < deadline:
        try:
            return oam.create_sink(**kwargs)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ServiceQuotaExceededException":
                last_exc = exc
                time.sleep(interval_s)
                continue
            raise
    raise last_exc


def _delete_sink_ignore_missing(oam, arn):
    try:
        oam.delete_sink(Identifier=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

