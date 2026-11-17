"""untag-resource-deleted-function-not-found-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "untag-resource-deleted-function-not-found-rejected"
GROUP = "overly-permissive"
SERVICES = ["cloudfront"]

_FUNCTION_CODE = b"""
function handler(event) {
    var request = event.request;
    return request;
}
""".strip()


def _error(fn):
    """Call fn(); return its botocore (code, message). An unexpected success raises, so an
    emulator accepting input real AWS refuses never reads as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UntagResource against a deleted function's ARN fails with NoSuchResource; the same call
    against the live function succeeds and actually removes the tag."""
    cf = ctx.client("cloudfront")
    name = ctx.unique_name("sim2real-fn-")

    created = cf.create_function(
        Name=name,
        FunctionConfig={"Comment": "sim2real behavioral check", "Runtime": "cloudfront-js-2.0"},
        FunctionCode=_FUNCTION_CODE,
    )
    function_arn = created["FunctionSummary"]["FunctionMetadata"]["FunctionARN"]
    etag = created["ETag"]
    ctx.on_cleanup(lambda: _delete_function_if_present(cf, name))

    cf.tag_resource(Resource=function_arn, Tags={"Items": [{"Key": "sim2real-owner", "Value": "behavioral"}]})
    tags_before = cf.list_tags_for_resource(Resource=function_arn)["Tags"]["Items"]
    assert {"Key": "sim2real-owner", "Value": "behavioral"} in tags_before, (
        f"expected the tag to be present after TagResource, got {tags_before!r}"
    )

    # Positive control: UntagResource against the live function succeeds and removes the tag.
    cf.untag_resource(Resource=function_arn, TagKeys={"Items": ["sim2real-owner"]})
    tags_after = cf.list_tags_for_resource(Resource=function_arn)["Tags"]["Items"]
    assert not any(t["Key"] == "sim2real-owner" for t in tags_after), (
        f"expected the tag removed after UntagResource, got {tags_after!r}"
    )

    cf.delete_function(Name=name, IfMatch=etag)

    # Error boundary: UntagResource against the now-deleted function's ARN is rejected.
    code, message = _error(
        lambda: cf.untag_resource(Resource=function_arn, TagKeys={"Items": ["sim2real-owner"]})
    )
    assert code == "NoSuchResource", f"expected NoSuchResource, got {code!r}: {message!r}"
    expected = "The specified resource doesn't exist. Update your request and try again."
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _delete_function_if_present(cf, name: str) -> None:
    try:
        etag = cf.describe_function(Name=name, Stage="DEVELOPMENT")["ETag"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "NoSuchFunctionExists":
            return
        raise
    cf.delete_function(Name=name, IfMatch=etag)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
