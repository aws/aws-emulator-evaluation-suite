"""create-link-invalid-sink-identifier-effect-absent."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-link-invalid-sink-identifier-effect-absent"
GROUP = "error-semantics"
SERVICES = ["oam"]
_SAME_ACCOUNT = "Cannot create a link to a sink in the same account"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:oam-sink")
def run(ctx) -> None:
    """CreateLink with a SinkIdentifier that breaks the ARN pattern fails with BadRequestException and
    the exact message and creates nothing, while a real same-account sink fails distinctly with
    InvalidParameterException and the exact message."""
    oam = ctx.client("oam")
    account_id = _own_account_id(ctx)

    sink_name = ctx.unique_name("sim2real-oam-sink-")
    sink = _create_sink_retrying(oam, sink_name, tags={"sim2real": CHECK})
    sink_arn = sink["Arn"]
    ctx.on_cleanup(lambda: _delete_sink_ignore_missing(oam, sink_arn))
    oam.put_sink_policy(SinkIdentifier=sink_arn, Policy=_own_account_sink_policy(account_id))

    bad_identifier = "not!a!valid!identifier"
    code, code_message = _error(
        lambda: oam.create_link(
            LabelTemplate="sim2real-bad-sink-label",
            ResourceTypes=["AWS::CloudWatch::Metric"],
            SinkIdentifier=bad_identifier,
        )
    )
    assert code == "BadRequestException", f"got {code!r}"
    assert code_message == _bad_identifier_message(bad_identifier), f"got message {code_message!r}"

    links_after = _list_all(oam.list_links, "Items", MaxResults=5)
    assert not any(link_ref_matches(item, bad_identifier) for item in links_after)
    attached = _list_all(oam.list_attached_links, "Items", SinkIdentifier=sink_arn)
    assert attached == [], f"got {attached!r}"

    # positive control: a well-formed SinkIdentifier naming a real sink is rejected too, but
    # distinctly -- as InvalidParameterException, not BadRequestException. This proves the check
    # can tell "malformed identifier" apart from "every CreateLink is denied here".
    good_code, good_code_message = _error(
        lambda: oam.create_link(
            LabelTemplate="sim2real-good-sink-label",
            ResourceTypes=["AWS::CloudWatch::Metric"],
            SinkIdentifier=sink_arn,
        )
    )
    assert good_code == "InvalidParameterException", f"got {good_code!r}"
    assert good_code_message == _SAME_ACCOUNT, f"got message {good_code_message!r}"
    attached_after = _list_all(oam.list_attached_links, "Items", SinkIdentifier=sink_arn)
    assert attached_after == [], f"got {attached_after!r}"


def link_ref_matches(item, bad_identifier):
    return bad_identifier in item.get("SinkArn", "")


def _bad_identifier_message(identifier):
    return (
        'Invalid request body: [ECMA 262 regex "^[a-zA-Z0-9][a-zA-Z0-9_:\\.\\-\\/]{0,2047}$" '
        f'does not match input string "{identifier}"]'
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
    while time.monotonic() < deadline:
        try:
            return oam.create_sink(Name=name, Tags=tags or {})
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
