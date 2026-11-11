"""sink-create-get-list-delete-lifecycle."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sink-create-get-list-delete-lifecycle"
GROUP = "state"
SERVICES = ["oam"]
_NOT_FOUND = "Resource not found."


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:oam-sink")
def run(ctx) -> None:
    """CreateSink -> GetSink -> ListSinks -> DeleteSink -> GetSink is NotFound, and the dead sink also rejects a mutation."""
    oam = ctx.client("oam")
    account_id = _own_account_id(ctx)
    name = ctx.unique_name("sim2real-oam-sink-")

    created = _create_sink_retrying(oam, name)
    arn = created["Arn"]
    sink_id = created["Id"]
    ctx.on_cleanup(lambda: _delete_sink_ignore_missing(oam, arn))
    assert created["Name"] == name, f"expected created sink Name={name!r}, got {created['Name']!r}"

    got = oam.get_sink(Identifier=arn)
    assert got["Arn"] == arn, f"expected GetSink Arn={arn!r}, got {got['Arn']!r}"
    assert got["Name"] == name, f"expected GetSink Name={name!r}, got {got['Name']!r}"
    assert got["Id"] == sink_id, f"expected GetSink Id={sink_id!r}, got {got['Id']!r}"

    items = _poll_until(
        lambda: _list_all(oam.list_sinks, "Items"),
        lambda items: any(i["Arn"] == arn for i in items),
        timeout_s=30.0,
        interval_s=2.0,
    )
    match = next(i for i in items if i["Arn"] == arn)
    assert match["Name"] == name, f"expected ListSinks entry Name={name!r}, got {match['Name']!r}"

    oam.delete_sink(Identifier=arn)

    code, code_message = _error(lambda: oam.get_sink(Identifier=arn))
    assert code == "ResourceNotFoundException", (
        f"expected GetSink on deleted sink to raise ResourceNotFoundException, got {code!r}"
    )
    assert code_message == _NOT_FOUND, f"got message {code_message!r}"

    dead_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Action": ["oam:CreateLink"],
                    "Effect": "Allow",
                    "Resource": "*",
                    "Principal": {"AWS": [account_id]},
                }
            ],
        }
    )
    mutate_code, mutate_code_message = _error(lambda: oam.put_sink_policy(SinkIdentifier=arn, Policy=dead_policy))
    assert mutate_code == "ResourceNotFoundException", (
        f"expected PutSinkPolicy on deleted sink to raise ResourceNotFoundException, got {mutate_code!r}"
    )
    assert mutate_code_message == _NOT_FOUND, f"got message {mutate_code_message!r}"


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


def _create_sink_retrying(oam, name, timeout_s=90.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return oam.create_sink(
                Name=name,
                Tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-oam-sink"},
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] in (
                "ServiceQuotaExceededException",
                "ConflictException",
            ):
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


def _poll_until(probe, predicate, timeout_s=30.0, interval_s=1.5):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
