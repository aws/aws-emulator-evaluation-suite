"""tag-resource-invalid-arn-effect-absent."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-resource-invalid-arn-effect-absent"
GROUP = "error-semantics"
SERVICES = ["oam"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:oam-sink")
def run(ctx) -> None:
    """TagResource on a malformed (non-oam) ARN is rejected and leaves a real sink's tags
    untouched; the identical operation against a well-formed ARN still succeeds."""
    oam = ctx.client("oam")

    sink_name = ctx.unique_name("sim2real-oam-sink-")
    sink = _create_sink_retrying(oam, sink_name)
    sink_arn = sink["Arn"]
    ctx.on_cleanup(lambda: _delete_sink_ignore_missing(oam, sink_arn))

    before = oam.list_tags_for_resource(ResourceArn=sink_arn)["Tags"]
    assert before == {}, f"expected no tags before the malformed call, got {before!r}"

    code, code_message = _error(
        lambda: oam.tag_resource(ResourceArn="not-an-oam-arn", Tags={"k": "v"})
    )
    assert code == "BadRequestException", f"got {code!r}"
    assert code_message == "Invalid input resource arn: bad syntax", f"got message {code_message!r}"

    # effect absent: the malformed-ARN call left the real sink's tags untouched.
    after_bad_call = oam.list_tags_for_resource(ResourceArn=sink_arn)["Tags"]
    assert after_bad_call == {}, f"expected no tags after the rejected call, got {after_bad_call!r}"

    # positive control: the identical Tags payload against the real sink's ARN succeeds.
    oam.tag_resource(ResourceArn=sink_arn, Tags={"k": "v"})
    tags = oam.list_tags_for_resource(ResourceArn=sink_arn)["Tags"]
    assert tags == {"k": "v"}, f"expected {{'k': 'v'}}, got {tags!r}"


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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
