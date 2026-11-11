"""create-link-duplicate-already-linked-conflict-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-link-duplicate-already-linked-conflict-rejected"
GROUP = "overly-permissive"
SERVICES = ["oam"]
_SAME_ACCOUNT = "Cannot create a link to a sink in the same account"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:oam-sink")
def run(ctx) -> None:
    """Repeated CreateLink calls to a sink in the caller's own account, with a permissive sink policy,
    each fail with InvalidParameterException and the exact message, and no link or attachment appears."""
    oam = ctx.client("oam")
    account_id = _own_account_id(ctx)

    sink_name = ctx.unique_name("sim2real-oam-sink-")
    sink = _create_sink_retrying(oam, sink_name, tags={"env": "sim2real", "purpose": "probe"})
    sink_arn = sink["Arn"]
    ctx.on_cleanup(lambda: _delete_sink_ignore_missing(oam, sink_arn))
    oam.put_sink_policy(SinkIdentifier=sink_arn, Policy=_own_account_sink_policy(account_id))

    for resource_types, label in (
        (["AWS::CloudWatch::Metric"], "sim2real-already-linked-1"),
        (["AWS::Logs::LogGroup"], "sim2real-already-linked-2"),
        (["AWS::CloudWatch::Metric", "AWS::Logs::LogGroup"], "sim2real-already-linked-3"),
    ):
        code, code_message = _error(
            lambda rt=resource_types, lb=label: oam.create_link(
                LabelTemplate=lb,
                ResourceTypes=rt,
                SinkIdentifier=sink_arn,
            )
        )
        assert code == "InvalidParameterException", f"got {code!r} for {resource_types}"
        assert code_message == _SAME_ACCOUNT, f"got message {code_message!r}"

    # effect absent: no link/attachment was ever created against the sink.
    attached = _list_all(oam.list_attached_links, "Items", SinkIdentifier=sink_arn)
    assert attached == [], f"expected no attached links, got {attached!r}"
    links = _list_all(oam.list_links, "Items", MaxResults=5)
    assert not any(item["SinkArn"] == sink_arn for item in links), (
        f"expected no link against {sink_arn!r} in {links!r}"
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


def _list_all(list_fn, items_key, **kwargs):
    items = []
    token = None
    while True:
        params = dict(kwargs)
        if token:
            params["NextToken"] = token
        resp = list_fn(**params)
        items.extend(resp.get(items_key, []))
        token = resp.get("NextToken")
        if not token:
            break
    return items


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

