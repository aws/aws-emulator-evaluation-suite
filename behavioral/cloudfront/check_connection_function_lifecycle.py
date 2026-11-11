"""connection-function-lifecycle."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "connection-function-lifecycle"
GROUP = "state-machine"
SERVICES = ["cloudfront"]

_CODE_V1 = b"""function connectionHandler(connection) {
    connection.allow();
}
"""
_CODE_V2 = b"""function connectionHandler(connection) {
    // sim2real-behav updated revision
    connection.allow();
}
"""


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Connection functions mirror the CloudFront Functions state machine: DEVELOPMENT -> LIVE, test, update."""
    cf = ctx.client("cloudfront")
    name = ctx.unique_name("sim2real-connfn-")

    if not hasattr(cf, "create_connection_function"):
        raise AssertionError("installed botocore does not support CreateConnectionFunction")

    try:
        created = cf.create_connection_function(
            Name=name,
            ConnectionFunctionConfig={"Comment": "sim2real-behav v1", "Runtime": "cloudfront-js-2.0"},
            ConnectionFunctionCode=_CODE_V1,
            Tags={"Items": [{"Key": "sim2real-check", "Value": CHECK}]},
        )
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        if code in ("UnsupportedOperation", "AccessDenied", "EntityLimitExceeded", "InvalidArgument"):
            raise AssertionError(f"connection functions unavailable/rejected for this account/region: {code}") from exc
        raise

    fn_id = created["ConnectionFunctionSummary"]["Id"]
    create_etag = created["ETag"]
    assert created["ConnectionFunctionSummary"]["Stage"] == "DEVELOPMENT"

    def _cleanup() -> None:
        try:
            etag = cf.get_connection_function(Identifier=fn_id)["ETag"]
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "EntityNotFound":
                return
            raise
        cf.delete_connection_function(Id=fn_id, IfMatch=etag)

    ctx.on_cleanup(_cleanup)

    described = cf.describe_connection_function(Identifier=fn_id)
    assert described["ConnectionFunctionSummary"]["Stage"] == "DEVELOPMENT"
    got = cf.get_connection_function(Identifier=fn_id)
    # GetConnectionFunction's ConnectionFunctionCode is the raw HTTP response payload (like
    # CloudFront Functions' GetFunction.FunctionCode) — botocore hands it back as a
    # streaming body, not bytes, so it must be read() before comparing.
    got_code = got["ConnectionFunctionCode"]
    if hasattr(got_code, "read"):
        got_code = got_code.read()
    assert got_code == _CODE_V1

    connection_object = json.dumps(
        {
            "clientIp": "192.0.2.1",
            "endpoint": "example.cloudfront.net",
            "distributionId": "EDFDVBD6EXAMPLE",
            "connectionId": "sim2real-behav-test-connection",
        }
    ).encode()
    test_result = cf.test_connection_function(
        Id=fn_id, IfMatch=create_etag, ConnectionObject=connection_object, Stage="DEVELOPMENT"
    )
    # Unlike CloudFront Functions' TestFunction (which wraps its payload under a generic
    # "TestResult" key), TestConnectionFunction follows the newer Connection Functions API's
    # naming convention of using the shape name itself as the member key — real AWS returns the
    # ConnectionFunctionTestResult structure under a "ConnectionFunctionTestResult" key, not
    # "TestResult".
    test_summary = test_result["ConnectionFunctionTestResult"]
    assert test_summary["ConnectionFunctionSummary"]["Id"] == fn_id
    assert not test_summary.get("ConnectionFunctionErrorMessage"), (
        f"test invocation of a function that only calls connection.allow() must not error, "
        f"got {test_summary.get('ConnectionFunctionErrorMessage')!r}"
    )

    published = cf.publish_connection_function(Id=fn_id, IfMatch=create_etag)
    assert published["ConnectionFunctionSummary"]["Stage"] == "LIVE", (
        "PublishConnectionFunction must promote DEVELOPMENT -> LIVE"
    )
    # DescribeConnectionFunction/GetConnectionFunction take an optional Stage query param,
    # mirroring CloudFront Functions' GetFunction/DescribeFunction: omitting it always fetches
    # the DEVELOPMENT copy, even after a publish. An independent confirmation of the LIVE
    # promotion has to ask for Stage="LIVE" explicitly.
    described_after_publish = cf.describe_connection_function(Identifier=fn_id, Stage="LIVE")
    described_stage = described_after_publish["ConnectionFunctionSummary"]["Stage"]
    assert described_stage == "LIVE", (
        f"an independent read of the LIVE stage after publish must observe LIVE, not just the "
        f"publish response, got Stage={described_stage!r}"
    )
    publish_etag = cf.get_connection_function(Identifier=fn_id)["ETag"]

    updated = cf.update_connection_function(
        Id=fn_id,
        IfMatch=publish_etag,
        ConnectionFunctionConfig={"Comment": "sim2real-behav v2", "Runtime": "cloudfront-js-2.0"},
        ConnectionFunctionCode=_CODE_V2,
    )
    assert updated["ConnectionFunctionSummary"]["Stage"] == "DEVELOPMENT", (
        "an update must revert the LIVE stage back to DEVELOPMENT"
    )
    update_etag = cf.get_connection_function(Identifier=fn_id)["ETag"]
    reread = cf.get_connection_function(Identifier=fn_id)
    reread_code = reread["ConnectionFunctionCode"]
    if hasattr(reread_code, "read"):
        reread_code = reread_code.read()
    assert reread_code == _CODE_V2

    cf.delete_connection_function(Id=fn_id, IfMatch=update_etag)

    deleted = False
    try:
        cf.get_connection_function(Identifier=fn_id)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "EntityNotFound":
            deleted = True
        else:
            raise
    assert deleted


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
