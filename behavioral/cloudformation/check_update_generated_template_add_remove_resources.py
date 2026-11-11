"""update-generated-template-add-remove-resources."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-generated-template-add-remove-resources"
GROUP = "data-plane"
SERVICES = ["cloudformation"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control", "resource:account-singleton:cfn-generated-template")
def run(ctx) -> None:
    """UpdateGeneratedTemplate Add/RemoveResources changes what GetGeneratedTemplate returns:
    the removed logical ID disappears and the added one appears with its identifying property."""
    cfn = ctx.client("cloudformation")
    s3 = ctx.client("s3")

    bucket_a = _create_bucket(ctx, s3, "sim2real-behav-gt-a-")
    bucket_b = _create_bucket(ctx, s3, "sim2real-behav-gt-b-")

    template_name = ctx.unique_name("sim2real-behav-gt-")
    cfn.create_generated_template(
        GeneratedTemplateName=template_name,
        Resources=[
            {
                "ResourceType": "AWS::S3::Bucket",
                "ResourceIdentifier": {"BucketName": bucket_a},
                "LogicalResourceId": "BucketA",
            }
        ],
    )
    ctx.on_cleanup(lambda: _delete_generated_template_if_present(cfn, template_name))
    _wait_generated_template(cfn, template_name)

    body_before = cfn.get_generated_template(
        GeneratedTemplateName=template_name, Format="JSON"
    )["TemplateBody"]
    resources_before = json.loads(body_before)["Resources"]
    assert "BucketA" in resources_before
    assert resources_before["BucketA"]["Properties"]["BucketName"] == bucket_a

    cfn.update_generated_template(
        GeneratedTemplateName=template_name,
        AddResources=[
            {
                "ResourceType": "AWS::S3::Bucket",
                "ResourceIdentifier": {"BucketName": bucket_b},
                "LogicalResourceId": "BucketB",
            }
        ],
        RemoveResources=["BucketA"],
    )
    _wait_generated_template(cfn, template_name)

    body_after = cfn.get_generated_template(
        GeneratedTemplateName=template_name, Format="JSON"
    )["TemplateBody"]
    resources_after = json.loads(body_after)["Resources"]
    assert "BucketA" not in resources_after
    assert "BucketB" in resources_after
    assert resources_after["BucketB"]["Properties"]["BucketName"] == bucket_b

    cfn.delete_generated_template(GeneratedTemplateName=template_name)
    deleted_code, deleted_message = _poll_until_error(
        cfn, template_name, timeout_s=120.0, interval_s=5.0
    )
    assert deleted_code == "GeneratedTemplateNotFound", (
        f"expected GeneratedTemplateNotFound after delete, got {deleted_code!r}: {deleted_message!r}"
    )
    # The message ends in a per-call request id: grade its stable prefix and suffix.
    assert deleted_message.startswith(f"Template with arn {template_name} does not exist (Service: ") and deleted_message.endswith(
        "; Proxy: null)"
    ), deleted_message

    rename_code, rename_message = _error(
        lambda: cfn.update_generated_template(
            GeneratedTemplateName=template_name,
            NewGeneratedTemplateName=template_name + "-renamed",
        )
    )
    assert rename_code == "GeneratedTemplateNotFound", (
        f"expected GeneratedTemplateNotFound mutating a deleted template, got {rename_code!r}: "
        f"{rename_message!r}"
    )
    # The message ends in a per-call request id: grade its stable prefix and suffix.
    assert rename_message.startswith(f"Template with arn {template_name} does not exist (Service: ") and rename_message.endswith(
        "; Proxy: null)"
    ), rename_message


def _create_bucket(ctx, s3, prefix):
    bucket = ctx.unique_name(prefix)
    if ctx.region == "us-east-1":
        # S3 CreateBucket rejects an explicit LocationConstraint in this one region.
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket))
    return bucket


def _error(fn):
    """Return the (code, message) of the ClientError ``fn`` raises; a success is a defect."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message", "")
    raise AssertionError(f"expected the call to be refused, but it succeeded and returned {result!r}")


def _delete_generated_template_if_present(cfn, name):
    """Teardown: the check deletes the template itself, so an already-gone template is done."""
    try:
        cfn.delete_generated_template(GeneratedTemplateName=name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "GeneratedTemplateNotFound":
            raise


def _poll_until_error(cfn, name, timeout_s=120.0, interval_s=5.0):
    """Poll DescribeGeneratedTemplate until it is refused; return the refusal's (code, message).
    RAISES if the template is still describable at the deadline."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            cfn.describe_generated_template(GeneratedTemplateName=name)
        except ClientError as exc:
            err = exc.response.get("Error", {})
            return err.get("Code"), err.get("Message", "")
        time.sleep(interval_s)
    raise AssertionError(f"generated template {name} still describable after delete within {timeout_s}s")


def _wait_generated_template(cfn, name, timeout_s=180.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        described = cfn.describe_generated_template(GeneratedTemplateName=name)
        status = described["Status"]
        if status == "COMPLETE":
            return described
        if status == "FAILED":
            raise AssertionError(f"generated template {name} failed: {described}")
        time.sleep(interval_s)
    raise AssertionError(f"generated template {name} did not complete within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
