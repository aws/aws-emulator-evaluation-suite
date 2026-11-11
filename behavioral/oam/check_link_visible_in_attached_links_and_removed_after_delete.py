"""link-visible-in-attached-links-and-removed-after-delete."""
from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "link-visible-in-attached-links-and-removed-after-delete"
GROUP = "state"
SERVICES = ["oam"]
_NOT_FOUND = "Resource not found."


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:oam-sink")
def run(ctx) -> None:
    """ListAttachedLinks on a fresh sink is an empty page, on a never-created sink fails with
    ResourceNotFoundException, and on a pattern-breaking SinkIdentifier fails with
    AccessDeniedException, each with the exact message."""
    oam = ctx.client("oam")

    sink_name = ctx.unique_name("sim2real-oam-sink-")
    sink = _create_sink_retrying(oam, sink_name)
    sink_arn = sink["Arn"]
    ctx.on_cleanup(lambda: _delete_sink_ignore_missing(oam, sink_arn))
    oam.tag_resource(ResourceArn=sink_arn, Tags={"env": "sim2real", "purpose": "probe"})

    items = _list_all(oam.list_attached_links, "Items", SinkIdentifier=sink_arn)
    assert items == [], f"expected no attached links on a fresh sink, got {items!r}"

    region = ctx.region
    account_id = _own_account_id(ctx)
    bogus_sink_arn = f"arn:aws:oam:{region}:{account_id}:sink/{uuid.uuid4()}"
    not_found_code, not_found_code_message = _error(
        lambda: oam.list_attached_links(SinkIdentifier=bogus_sink_arn)
    )
    assert not_found_code == "ResourceNotFoundException", f"got {not_found_code!r}"
    assert not_found_code_message == _NOT_FOUND, f"got message {not_found_code_message!r}"

    # distinct boundary: a SinkIdentifier that doesn't even match the ARN/name pattern is
    # rejected at request-shape validation, distinctly from the "well-formed but absent" case.
    malformed_code, malformed_code_message = _error(
        lambda: oam.list_attached_links(SinkIdentifier="not!a!valid!identifier")
    )
    assert malformed_code == "AccessDeniedException", f"got {malformed_code!r}"
    assert malformed_code_message == _explicit_deny_message(ctx, "ListAttachedLinks", f"arn:aws:oam:{region}:{account_id}:sink/*"), f"got message {malformed_code_message!r}"

    # positive control: the real (empty) sink is accepted and returns a well-formed page.
    ok = oam.list_attached_links(SinkIdentifier=sink_arn, MaxResults=50)
    assert ok["Items"] == [], f"expected an empty well-formed page, got {ok['Items']!r}"


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

