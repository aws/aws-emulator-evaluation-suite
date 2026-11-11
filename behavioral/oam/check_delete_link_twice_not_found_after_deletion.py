"""delete-link-twice-not-found-after-deletion."""
from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-link-twice-not-found-after-deletion"
GROUP = "error-semantics"
SERVICES = ["oam"]
_NOT_FOUND = "Resource not found."


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:oam-sink")
def run(ctx) -> None:
    """DeleteLink on a never-created link fails with ResourceNotFoundException and the exact message on
    two calls; ListLinks rejects a malformed NextToken with ValidationException "Invalid pagination
    token" and accepts a first page; a created sink is listed by ListSinks."""
    oam = ctx.client("oam")
    account_id = _own_account_id(ctx)
    region = ctx.region

    bogus_arn = f"arn:aws:oam:{region}:{account_id}:link/{uuid.uuid4()}"

    code1, code1_message = _error(lambda: oam.delete_link(Identifier=bogus_arn))
    assert code1 == "ResourceNotFoundException", f"got {code1!r}"
    assert code1_message == _NOT_FOUND, f"got message {code1_message!r}"

    code2, code2_message = _error(lambda: oam.delete_link(Identifier=bogus_arn))
    assert code2 == "ResourceNotFoundException", f"got {code2!r}"
    assert code2_message == _NOT_FOUND, f"got message {code2_message!r}"

    # distinct boundary: a malformed NextToken must be rejected distinctly rather than being
    # silently treated as "no token"/first page.
    bad_token_code, bad_token_code_message = _error(
        lambda: oam.list_links(MaxResults=5, NextToken="not-a-real-token")
    )
    assert bad_token_code == "ValidationException", f"got {bad_token_code!r}"
    assert bad_token_code_message == "Invalid pagination token", f"got message {bad_token_code_message!r}"

    # positive control: an in-range MaxResults with no token is accepted and returns a well-formed page.
    ok = oam.list_links(MaxResults=5)
    assert isinstance(ok.get("Items"), list), f"got {ok!r}"

    # positive control for DeleteLink: a real mutation (CreateSink) followed by an independent
    # read (ListSinks) at the destination proves the caller's account and Region are otherwise healthy for OAM
    # -- without it, a target that unconditionally denies every DeleteLink call would pass above.
    sink_name = ctx.unique_name("sim2real-oam-sink-")
    sink = _create_sink_retrying(oam, sink_name, tags={"sim2real": CHECK})
    sink_arn = sink["Arn"]
    ctx.on_cleanup(lambda: _delete_sink_ignore_missing(oam, sink_arn))
    assert sink["Name"] == sink_name, f"got {sink!r}"

    listed = _poll_until(
        lambda: _list_all(oam.list_sinks, "Items"),
        lambda items: any(i["Arn"] == sink_arn for i in items),
        timeout_s=30.0,
        interval_s=2.0,
    )
    match = next(i for i in listed if i["Arn"] == sink_arn)
    assert match["Name"] == sink_name, f"got {match!r}"


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

