"""create-link-invalid-resource-type-effect-absent."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-link-invalid-resource-type-effect-absent"
GROUP = "error-semantics"
SERVICES = ["oam"]
_SAME_ACCOUNT = "Cannot create a link to a sink in the same account"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:oam-sink")
def run(ctx) -> None:
    """CreateLink with an unsupported ResourceTypes enum value is rejected and creates nothing."""
    oam = ctx.client("oam")
    account_id = _own_account_id(ctx)

    sink_name = ctx.unique_name("sim2real-oam-sink-")
    sink = _create_sink_retrying(oam, sink_name, tags={"env": "sim2real", "purpose": "probe"})
    sink_arn = sink["Arn"]
    ctx.on_cleanup(lambda: _delete_sink_ignore_missing(oam, sink_arn))
    oam.put_sink_policy(SinkIdentifier=sink_arn, Policy=_own_account_sink_policy(account_id))

    code, message = _error(
        lambda: oam.create_link(
            LabelTemplate="sim2real-bad-type-label",
            ResourceTypes=["AWS::Bogus::NotARealType"],
            SinkIdentifier=sink_arn,
        )
    )
    assert code == "BadRequestException", f"got {code!r}"
    # message varies: it lists every ResourceTypes enum value OAM supports, which grows as OAM
    # adds resource types, so the stable text around that list is asserted exactly.
    prefix = (
        'Invalid request body: [instance value ("AWS::Bogus::NotARealType") not found in enum '
        "(possible values: ["
    )
    assert message.startswith(prefix) and message.endswith("])]"), (
        f"expected the enum-membership refusal {prefix!r}...])], got {message!r}"
    )
    assert '"AWS::CloudWatch::Metric"' in message[len(prefix):], (
        f"expected the possible values to list AWS::CloudWatch::Metric, got {message!r}"
    )

    attached = _list_all(oam.list_attached_links, "Items", SinkIdentifier=sink_arn)
    assert attached == [], f"a link with an unsupported ResourceTypes value got attached: {attached!r}"

    # positive control: CreateLink to a sink in the SAME account is disallowed regardless of
    # ResourceTypes validity (cross-account is the whole point of OAM) -- a well-formed request
    # still gets rejected, distinctly, as InvalidParameterException with no link created.
    good_code, good_code_message = _error(
        lambda: oam.create_link(
            LabelTemplate="sim2real-good-type-label",
            ResourceTypes=["AWS::CloudWatch::Metric"],
            SinkIdentifier=sink_arn,
        )
    )
    assert good_code == "InvalidParameterException", f"got {good_code!r}"
    assert good_code_message == _SAME_ACCOUNT, f"got message {good_code_message!r}"
    attached_after = _list_all(oam.list_attached_links, "Items", SinkIdentifier=sink_arn)
    assert attached_after == [], (
        f"a same-account link got attached despite the rejection: {attached_after!r}"
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


def _delete_link_ignore_missing(oam, arn):
    try:
        oam.delete_link(Identifier=arn)
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
