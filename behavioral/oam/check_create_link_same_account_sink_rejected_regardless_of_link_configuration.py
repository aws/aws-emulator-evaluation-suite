"""create-link-same-account-sink-rejected-regardless-of-link-configuration."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-link-same-account-sink-rejected-regardless-of-link-configuration"
GROUP = "error-semantics"
SERVICES = ["oam"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:oam-sink")
def run(ctx) -> None:
    """CreateLink to a same-account sink fails with InvalidParameterException and the identical
    message whether LinkConfiguration mismatches ResourceTypes or is well-formed, and attaches nothing
    to the sink."""
    oam = ctx.client("oam")
    account_id = _own_account_id(ctx)

    sink_name = ctx.unique_name("sim2real-oam-sink-")
    sink = _create_sink_retrying(oam, sink_name, tags={"sim2real-check": CHECK})
    sink_arn = sink["Arn"]
    ctx.on_cleanup(lambda: _delete_sink_ignore_missing(oam, sink_arn))
    oam.put_sink_policy(SinkIdentifier=sink_arn, Policy=_own_account_sink_policy(account_id))

    # LogGroupConfiguration supplied but ResourceTypes only declares Metric -- a structural
    # mismatch that, if the service validated it before the same-account gate, would be
    # rejectable on its own terms.
    mismatch_code, mismatch_msg = _error_code_and_message(
        lambda: oam.create_link(
            LabelTemplate="sim2real-filter-mismatch-label",
            ResourceTypes=["AWS::CloudWatch::Metric"],
            SinkIdentifier=sink_arn,
            LinkConfiguration={"LogGroupConfiguration": {"Filter": "*"}},
        )
    )
    assert mismatch_code == "InvalidParameterException", f"got {mismatch_code!r}"

    # a well-formed LinkConfiguration matching ResourceTypes is STILL rejected -- same-account
    # linking is disallowed regardless of how well-formed the configuration is.
    wellformed_code, wellformed_msg = _error_code_and_message(
        lambda: oam.create_link(
            LabelTemplate="sim2real-filter-wellformed-label",
            ResourceTypes=["AWS::CloudWatch::Metric", "AWS::Logs::LogGroup"],
            SinkIdentifier=sink_arn,
            LinkConfiguration={
                "MetricConfiguration": {"Filter": "Namespace = 'AWS/EC2'"},
                "LogGroupConfiguration": {"Filter": "LogGroupName LIKE 'aws/lambda/%'"},
            },
        )
    )
    assert wellformed_code == "InvalidParameterException", f"got {wellformed_code!r}"

    # the two rejections are not merely the same code -- they carry the identical message, proof
    # that the same-account gate fired both times without ever distinguishing the two
    # LinkConfiguration bodies.
    assert mismatch_msg == wellformed_msg, f"{mismatch_msg!r} != {wellformed_msg!r}"

    # effect absent in both cases: nothing was attached to the sink.
    attached = _list_all(oam.list_attached_links, "Items", SinkIdentifier=sink_arn)
    assert attached == [], f"expected no attached links, got {attached!r}"


def _error_code_and_message(fn):
    """Call fn(); return (Code, Message). An unexpected SUCCESS raises, because an emulator
    ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response["Error"]
        return error["Code"], error["Message"]
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


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

