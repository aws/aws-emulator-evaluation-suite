"""generated-template-not-found-error."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "generated-template-not-found-error"
GROUP = "error-semantics"
SERVICES = ["cloudformation"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:cfn-generated-template")
def run(ctx) -> None:
    """GetGeneratedTemplate on a name derived from a real generated template fails with
    GeneratedTemplateNotFound "Template with arn <name> does not exist ...", while the same
    call on the real template succeeds with a Status."""
    cfn = ctx.client("cloudformation")
    s3 = ctx.client("s3")

    bucket = ctx.unique_name("sim2real-behav-nogt-").replace("_", "-").lower()
    kwargs = {"Bucket": bucket}
    # S3 CreateBucket rejects an explicit LocationConstraint of "us-east-1" (its
    # own default region) with InvalidLocationConstraint — the literal names that
    # one region's special case, not a pin of the check to it.
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: _delete_bucket(s3, bucket))

    real_name = ctx.unique_name("sim2real-behav-gt-")
    cfn.create_generated_template(
        GeneratedTemplateName=real_name,
        Resources=[{"ResourceType": "AWS::S3::Bucket", "ResourceIdentifier": {"BucketName": bucket}}],
    )
    ctx.on_cleanup(lambda: _best_effort_delete_template(cfn, real_name))

    try:
        positive = cfn.get_generated_template(GeneratedTemplateName=real_name)
    except ClientError as exc:
        raise AssertionError(
            "positive control failed: GetGeneratedTemplate on a template this "
            f"check just created raised {exc.response['Error']['Code']!r}"
        ) from exc
    assert positive.get("Status"), f"expected a non-empty Status on the real template, got {positive!r}"

    bogus_name = real_name + "-does-not-exist"
    # Real CloudFormation reports this via the awsQuery error code "GeneratedTemplateNotFound"
    # (no "Exception" suffix), unlike most other CFN not-found errors.
    error = _expect_error(
        lambda: cfn.get_generated_template(GeneratedTemplateName=bogus_name)
    ).response["Error"]
    code, message = error["Code"], error.get("Message", "")
    assert code == "GeneratedTemplateNotFound", f"expected GeneratedTemplateNotFound, got {code}"
    # The message ends in a per-call request id: grade its stable prefix and suffix.
    assert message.startswith(f"Template with arn {bogus_name} does not exist (Service: ") and message.endswith(
        "; Proxy: null)"
    ), message


def _expect_error(fn):
    """Call fn(); return the raised ClientError. Raise if fn() succeeds unexpectedly."""
    try:
        result = fn()
    except ClientError as exc:
        return exc
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _best_effort_delete_template(cfn, name: str, *, timeout_s: float = 600.0, interval_s: float = 10.0) -> None:
    """Teardown: a just-created template is still generating and refuses deletion until then, so
    retry while its operation is in progress; a template already gone is fine."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            cfn.delete_generated_template(GeneratedTemplateName=name)
            return
        except ClientError as exc:
            error = exc.response["Error"]
            if error["Code"] == "GeneratedTemplateNotFound":
                return
            in_progress = error["Code"] == "ValidationError" and "operation in progress" in error.get("Message", "")
            if not in_progress or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


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
