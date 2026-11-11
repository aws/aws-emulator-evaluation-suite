"""create-sink-duplicate-name-conflict-effect-absent."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-sink-duplicate-name-conflict-effect-absent"
GROUP = "error-semantics"
SERVICES = ["oam"]
_NOT_FOUND = "Resource not found."


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:oam-sink")
def run(ctx) -> None:
    """This account/region allows only one sink at a time: a second CreateSink call -- even with
    a DIFFERENT name -- is rejected by the quota, not silently accepted or conflated with the
    "duplicate name" case; freeing the existing sink lets a new one be created."""
    oam = ctx.client("oam")
    name = ctx.unique_name("sim2real-oam-sink-")

    first = _create_sink_retrying(oam, name)
    first_arn = first["Arn"]
    ctx.on_cleanup(lambda: _delete_sink_ignore_missing(oam, first_arn))

    # same name again: rejected by the account-level sink quota (there can only be one sink).
    same_name_code, same_name_code_message = _error(lambda: oam.create_sink(Name=name))
    assert same_name_code == "ServiceQuotaExceededException", f"got {same_name_code!r}"
    assert same_name_code_message == _quota_message(ctx.account), f"got message {same_name_code_message!r}"

    # a DIFFERENT name is rejected the exact same way -- it's the quota, not name collision.
    other_name = ctx.unique_name("sim2real-oam-sink-2-")
    diff_name_code, diff_name_code_message = _error(lambda: oam.create_sink(Name=other_name))
    assert diff_name_code == "ServiceQuotaExceededException", f"got {diff_name_code!r}"
    assert diff_name_code_message == _quota_message(ctx.account), f"got message {diff_name_code_message!r}"

    sinks = _list_all(oam.list_sinks, "Items")
    assert any(i["Arn"] == first_arn for i in sinks), f"{first_arn} missing from {sinks!r}"
    assert not any(
        i["Name"] == other_name for i in sinks
    ), f"rejected sink {other_name!r} unexpectedly appeared in {sinks!r}"

    # positive control (sequential, since only one sink may exist per account/region):
    # freeing the slot lets a differently-named sink be created.
    oam.delete_sink(Identifier=first_arn)
    deleted_code, deleted_code_message = _error(lambda: oam.get_sink(Identifier=first_arn))
    assert deleted_code == "ResourceNotFoundException", f"got {deleted_code!r}"
    assert deleted_code_message == _NOT_FOUND, f"got message {deleted_code_message!r}"

    second = _create_sink_retrying(oam, other_name)
    second_arn = second["Arn"]
    ctx.on_cleanup(lambda: _delete_sink_ignore_missing(oam, second_arn))
    assert second["Name"] == other_name, f"expected {other_name!r}, got {second['Name']!r}"

    # independent read at the destination, through a different operation than the mutation.
    final_sinks = _list_all(oam.list_sinks, "Items")
    assert any(i["Arn"] == second_arn and i["Name"] == other_name for i in final_sinks), (
        f"{second_arn} with name {other_name!r} missing from {final_sinks!r}"
    )


def _quota_message(account_id):
    return f"Reached account sink max(1) for account({account_id})."


def _error(fn):
    """Call fn(), which must fail; return its botocore error (code, message). An unexpected
    SUCCESS raises, so a target that accepts what AWS refuses is never read as a mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response["Error"]
        return error["Code"], error.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _create_sink_retrying(oam, name, timeout_s=90.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return oam.create_sink(Name=name)
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

