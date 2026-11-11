"""generated-template-full-lifecycle."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "generated-template-full-lifecycle"
GROUP = "state-machine"
SERVICES = ["cloudformation"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:cfn-generated-template")
def run(ctx) -> None:
    """CreateGeneratedTemplate moves CREATE_PENDING->...->COMPLETE, and the
    resulting template is gettable, updatable (rename), listable, and deletable."""
    cfn = ctx.client("cloudformation")
    s3 = ctx.client("s3")

    bucket = ctx.unique_name("sim2real-cfngen-").replace("_", "-").lower()
    kwargs = {"Bucket": bucket}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: _delete_bucket(ctx, bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real-check", "Value": CHECK}]})

    name = ctx.unique_name("sim2real-gentpl-")
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
    assert described["Status"] == "COMPLETE", described.get("StatusReason")
    assert described["Resources"][0]["ResourceIdentifier"]["BucketName"] == bucket

    got = cfn.get_generated_template(GeneratedTemplateName=name)
    assert got["Status"] == "COMPLETE"
    assert bucket in got["TemplateBody"]

    names_before = {s["GeneratedTemplateName"] for s in cfn.list_generated_templates()["Summaries"]}
    assert name in names_before

    new_name = name + "-renamed"
    cfn.update_generated_template(GeneratedTemplateName=name, NewGeneratedTemplateName=new_name)
    ctx.on_cleanup(lambda: _best_effort_delete_template(cfn, new_name))
    described_renamed = _poll_until(
        lambda: cfn.describe_generated_template(GeneratedTemplateName=new_name),
        lambda d: d["Status"] in ("COMPLETE", "FAILED"),
        timeout_s=180,
        interval_s=5,
    )
    assert described_renamed["Status"] == "COMPLETE"

    names_after_rename = {s["GeneratedTemplateName"] for s in cfn.list_generated_templates()["Summaries"]}
    assert new_name in names_after_rename
    assert name not in names_after_rename

    cfn.delete_generated_template(GeneratedTemplateName=new_name)
    # DeleteGeneratedTemplate is asynchronous: DescribeGeneratedTemplate can keep
    # succeeding (transient DELETE_PENDING/DELETE_IN_PROGRESS status) for a short
    # window before the record is actually removed and lookups start failing.
    # A by-name lookup for a deleted generated template fails with GeneratedTemplateNotFound.
    deleted = _expect_error(
        lambda: cfn.describe_generated_template(GeneratedTemplateName=new_name),
        timeout_s=120,
        interval_s=5,
    ).response["Error"]
    deleted_code, message = deleted["Code"], deleted.get("Message", "")
    assert deleted_code == "GeneratedTemplateNotFound", deleted_code
    # The message ends in a per-call request id: grade its stable prefix and suffix.
    assert message.startswith(f"Template with arn {new_name} does not exist (Service: ") and message.endswith(
        "; Proxy: null)"
    ), message

    # The dead id is not just unreadable but unusable: a mutation against it must
    # fail the same specific way, not silently no-op or succeed a second time.
    double_delete = _expect_error(
        lambda: cfn.delete_generated_template(GeneratedTemplateName=new_name)
    ).response["Error"]
    double_delete_code, message = double_delete["Code"], double_delete.get("Message", "")
    assert double_delete_code == "GeneratedTemplateNotFound", double_delete_code
    # The message ends in a per-call request id: grade its stable prefix and suffix.
    assert message.startswith(f"Template with arn {new_name} does not exist (Service: ") and message.endswith(
        "; Proxy: null)"
    ), message


def _expect_error(fn, *, timeout_s=0.0, interval_s=5.0):
    """Call fn() until it raises a ClientError and return that error. A call that keeps
    SUCCEEDING past timeout_s raises AssertionError (timeout_s=0 means one attempt)."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            result = fn()
        except ClientError as exc:
            return exc
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"expected a ClientError, but the call kept SUCCEEDING for {timeout_s}s; last={result!r}"
            )
        time.sleep(interval_s)


def _poll_until(probe, predicate, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    result = probe()
    while not predicate(result):
        if time.monotonic() > deadline:
            raise AssertionError(f"condition not met within {timeout_s}s; last result={result}")
        time.sleep(interval_s)
        result = probe()
    return result


def _best_effort_delete_template(cfn, name: str) -> None:
    try:
        cfn.delete_generated_template(GeneratedTemplateName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "GeneratedTemplateNotFound":
            raise


def _delete_bucket(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
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
