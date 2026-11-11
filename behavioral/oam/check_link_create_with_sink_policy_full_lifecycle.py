"""link-create-with-sink-policy-full-lifecycle."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "link-create-with-sink-policy-full-lifecycle"
GROUP = "state"
SERVICES = ["oam"]
_NOT_FOUND = "Resource not found."


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:oam-sink")
def run(ctx) -> None:
    """CreateSink accepts Tags directly at creation (no separate TagResource call needed), and
    both the sink's policy and its tags are gone -- not just the sink -- once DeleteSink runs."""
    oam = ctx.client("oam")
    account_id = _own_account_id(ctx)

    sink_name = ctx.unique_name("sim2real-oam-sink-")
    sink = _create_sink_retrying(oam, sink_name, tags={"env": "sim2real", "purpose": "probe"})
    sink_arn = sink["Arn"]
    ctx.on_cleanup(lambda: _delete_sink_ignore_missing(oam, sink_arn))

    # Tags supplied at CreateSink time are immediately visible without a separate TagResource call.
    created_tags = sink.get("Tags")
    assert created_tags == {"env": "sim2real", "purpose": "probe"}, f"got {created_tags!r}"
    tags_via_list = oam.list_tags_for_resource(ResourceArn=sink_arn)["Tags"]
    assert tags_via_list == {"env": "sim2real", "purpose": "probe"}, f"got {tags_via_list!r}"

    oam.put_sink_policy(SinkIdentifier=sink_arn, Policy=_own_account_sink_policy(account_id))
    policy_sink_arn = oam.get_sink_policy(SinkIdentifier=sink_arn)["SinkArn"]
    assert policy_sink_arn == sink_arn, f"got {policy_sink_arn!r}"

    oam.delete_sink(Identifier=sink_arn)

    get_code, get_code_message = _error(lambda: oam.get_sink(Identifier=sink_arn))
    assert get_code == "ResourceNotFoundException", f"got {get_code!r}"
    assert get_code_message == _NOT_FOUND, f"got message {get_code_message!r}"
    policy_code, policy_code_message = _error(lambda: oam.get_sink_policy(SinkIdentifier=sink_arn))
    assert policy_code == "ResourceNotFoundException", f"got {policy_code!r}"
    assert policy_code_message == _NOT_FOUND, f"got message {policy_code_message!r}"
    tags_code, tags_code_message = _error(lambda: oam.list_tags_for_resource(ResourceArn=sink_arn))
    assert tags_code == "NotFoundException", f"got {tags_code!r}"
    assert tags_code_message == "Resource was not found", f"got message {tags_code_message!r}"

    # A mutation on the dead id must also fail, not just reads.
    put_policy_code, put_policy_code_message = _error(
        lambda: oam.put_sink_policy(
            SinkIdentifier=sink_arn, Policy=_own_account_sink_policy(account_id)
        )
    )
    assert put_policy_code == "ResourceNotFoundException", f"got {put_policy_code!r}"
    assert put_policy_code_message == _NOT_FOUND, f"got message {put_policy_code_message!r}"


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


