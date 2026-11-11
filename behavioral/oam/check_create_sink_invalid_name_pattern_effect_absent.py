"""create-sink-invalid-name-pattern-effect-absent."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-sink-invalid-name-pattern-effect-absent"
GROUP = "error-semantics"
SERVICES = ["oam"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:oam-sink")
def run(ctx) -> None:
    """CreateSink with a name violating the allowed pattern is rejected and creates no sink."""
    oam = ctx.client("oam")

    bad_name = "bad name!"
    code, code_message = _error(lambda: oam.create_sink(Name=bad_name))
    assert code == "BadRequestException", f"got {code!r}"
    assert code_message == _bad_name_message(bad_name), f"got message {code_message!r}"

    sinks = _list_all(oam.list_sinks, "Items")
    assert not any(i["Name"] == bad_name for i in sinks)

    # positive control: a name matching the allowed pattern succeeds.
    good_name = ctx.unique_name("sim2real-oam-sink-")
    created = _create_sink_retrying(oam, good_name)
    arn = created["Arn"]
    ctx.on_cleanup(lambda: _delete_sink_ignore_missing(oam, arn))
    assert created["Name"] == good_name

    # independent read at the destination: the mutating call's own echo is not the terminal
    # assertion -- confirm the sink is actually visible via GetSink.
    got = oam.get_sink(Identifier=arn)
    assert got["Arn"] == arn
    assert got["Name"] == good_name


def _bad_name_message(name):
    return (
        'Invalid request body: [ECMA 262 regex "^[a-zA-Z0-9_\\.\\-]{1,255}$" '
        f'does not match input string "{name}"]'
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


def _create_sink_retrying(oam, name, timeout_s=90.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return oam.create_sink(Name=name, Tags={"sim2real": CHECK})
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
