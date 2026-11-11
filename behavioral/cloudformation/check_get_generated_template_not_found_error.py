"""get-generated-template-not-found-error."""
from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-generated-template-not-found-error"
GROUP = "error-semantics"
SERVICES = ["cloudformation"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:cfn-generated-template")
def run(ctx) -> None:
    """GetGeneratedTemplate on a real generated template succeeds (positive control);
    the identical call against an unknown generated template ARN returns the wire error
    code GeneratedTemplateNotFound, never a success."""
    cfn = ctx.client("cloudformation")
    s3 = ctx.client("s3")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    bucket = ctx.unique_name("sim2real-ggtnf-").replace("_", "-").lower()
    kwargs = {"Bucket": bucket}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: _delete_bucket(s3, bucket))

    name = ctx.unique_name("sim2real-ggtnf-tpl-")
    cfn.create_generated_template(
        GeneratedTemplateName=name,
        Resources=[{"ResourceType": "AWS::S3::Bucket", "ResourceIdentifier": {"BucketName": bucket}}],
    )
    ctx.on_cleanup(lambda: _best_effort_delete_template(cfn, name))

    described = _poll_until(
        lambda: cfn.describe_generated_template(GeneratedTemplateName=name),
        lambda d: d["Status"] in ("COMPLETE", "FAILED"),
        timeout_s=180,
        interval_s=5,
    )
    assert described["Status"] == "COMPLETE", (
        f"positive-control template did not reach COMPLETE: {described.get('StatusReason')}"
    )

    # Positive control: GetGeneratedTemplate on a real, existing template succeeds and
    # returns real content -- without this, a target that unconditionally rejects
    # GetGeneratedTemplate would score identically to a correctly-behaving one.
    got = cfn.get_generated_template(GeneratedTemplateName=name)
    assert got["Status"] == "COMPLETE", got
    assert bucket in got["TemplateBody"], got["TemplateBody"]

    bogus_arn = (
        f"arn:aws:cloudformation:{ctx.region}:{account_id}:generatedtemplate/{uuid.uuid4()}"
    )
    # Real AWS returns the wire error code "GeneratedTemplateNotFound" (no "Exception" suffix) --
    # distinct from the modeled botocore exception class name GeneratedTemplateNotFoundException.
    code, message = _error_code(lambda: cfn.get_generated_template(GeneratedTemplateName=bogus_arn))
    assert code == "GeneratedTemplateNotFound", (
        f"expected GeneratedTemplateNotFound, got {code}"
    )
    # The message ends in a per-call request id: grade its stable prefix and suffix.
    assert message.startswith(f"Template with arn {bogus_arn} does not exist (Service: ") and message.endswith(
        "; Proxy: null)"
    ), message

    # The rejection of the bogus ARN did not disturb the real template: the identical
    # successful call against it still succeeds afterward.
    got_again = cfn.get_generated_template(GeneratedTemplateName=name)
    assert got_again["Status"] == "COMPLETE", got_again


def _error_code(fn):
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(
        f"expected a rejection, but the call SUCCEEDED and returned {result!r}"
    )


def _poll_until(probe, predicate, *, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    result = probe()
    while not predicate(result):
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout_s}s; last value={result!r}")
        time.sleep(interval_s)
        result = probe()
    return result


def _best_effort_delete_template(cfn, name: str) -> None:
    try:
        cfn.delete_generated_template(GeneratedTemplateName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "GeneratedTemplateNotFound":
            raise


def _delete_bucket(s3, bucket: str) -> None:
    try:
        resp = s3.list_objects_v2(Bucket=bucket)
        objs = [{"Key": o["Key"]} for o in resp.get("Contents", [])]
        if objs:
            failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": objs}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
