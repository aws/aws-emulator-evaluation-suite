"""update-generated-template-name-conflict."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "update-generated-template-name-conflict"
GROUP = "error-semantics"
SERVICES = ["cloudformation"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control", "resource:account-singleton:cfn-generated-template")
def run(ctx) -> None:
    """UpdateGeneratedTemplate renaming a template to another template's name fails with
    AlreadyExistsException "Template with name <name> already exists. ..." and leaves both templates
    as they were; a rename to a free name succeeds, as does the same rename once the name is freed."""
    s3 = ctx.client("s3")
    cfn = ctx.client("cloudformation")

    bucket_name = ctx.unique_name("sim2real-behav-gt-").lower().replace("_", "-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket_name)
    else:
        s3.create_bucket(
            Bucket=bucket_name,
            CreateBucketConfiguration={"LocationConstraint": ctx.region},
        )
    s3.put_bucket_tagging(
        Bucket=bucket_name, Tagging={"TagSet": [{"Key": "sim2real-check", "Value": CHECK}]}
    )
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket_name))

    resources = [
        {"ResourceType": "AWS::S3::Bucket", "ResourceIdentifier": {"BucketName": bucket_name}}
    ]

    name_a = ctx.unique_name("sim2real-behav-gtA-")
    name_b = ctx.unique_name("sim2real-behav-gtB-")
    name_pos = ctx.unique_name("sim2real-behav-gtP-")
    name_pos2 = ctx.unique_name("sim2real-behav-gtP2-")

    cfn.create_generated_template(GeneratedTemplateName=name_a, Resources=resources)
    ctx.on_cleanup(lambda: _delete_generated_template_quiet(cfn, name_a))
    cfn.create_generated_template(GeneratedTemplateName=name_b, Resources=resources)
    ctx.on_cleanup(lambda: _delete_generated_template_quiet(cfn, name_b))
    cfn.create_generated_template(GeneratedTemplateName=name_pos, Resources=resources)
    ctx.on_cleanup(lambda: _delete_generated_template_quiet(cfn, name_pos))
    ctx.on_cleanup(lambda: _delete_generated_template_quiet(cfn, name_pos2))

    # Let template generation settle into a terminal status before probing any rename, so the
    # AlreadyExistsException we assert on is unambiguously about the name conflict and not some
    # transient in-progress conflict.
    for name in (name_a, name_b, name_pos):
        if not _wait_for_generated_template_terminal(ctx, name, timeout_s=180.0):
            raise AssertionError(
                f"generated template {name} never reached a terminal status in time",
            )

    # Positive control: the same call shape, renaming to a name nothing else holds, succeeds
    # and is observable at an independent read -- both that the new name now resolves and
    # that the old one does not.
    cfn.update_generated_template(GeneratedTemplateName=name_pos, NewGeneratedTemplateName=name_pos2)
    if not _wait_for_generated_template_terminal(ctx, name_pos2, timeout_s=180.0):
        raise AssertionError(
            f"positive control: renamed template {name_pos2} never reached a terminal status in time",
        )
    old_pos_code, message = _poll_until_notfound(cfn, name_pos, timeout_s=120.0)
    assert old_pos_code == "GeneratedTemplateNotFound", (
        f"positive control: {name_pos} should be gone after a successful rename to "
        f"{name_pos2}, but describing it returned {old_pos_code!r}"
    )
    # The message ends in a per-call request id: grade its stable prefix and suffix.
    assert message.startswith(f"Template with arn {name_pos} does not exist (Service: ") and message.endswith(
        "; Proxy: null)"
    ), message

    # Negative: renaming name_a to the name already held by name_b is rejected.
    code, message = _error(
        lambda: cfn.update_generated_template(
            GeneratedTemplateName=name_a, NewGeneratedTemplateName=name_b
        )
    )
    assert code == "AlreadyExistsException", f"expected AlreadyExistsException, got {code}: {message!r}"
    # The message ends in a per-call request id: grade its stable prefix and suffix.
    assert message.startswith(f"Template with name {name_b} already exists. (Service: ") and message.endswith(
        "; Proxy: null)"
    ), message

    # Effect-absent: the rejected rename touched neither side of the conflict.
    described_a = cfn.describe_generated_template(GeneratedTemplateName=name_a)
    assert described_a["GeneratedTemplateName"] == name_a, (
        f"the rejected rename changed {name_a}'s own name: "
        f"{described_a.get('GeneratedTemplateName')!r}"
    )
    described_b = cfn.describe_generated_template(GeneratedTemplateName=name_b)
    assert described_b["GeneratedTemplateName"] == name_b, (
        f"the rejected rename touched the collision target {name_b}: "
        f"{described_b.get('GeneratedTemplateName')!r}"
    )

    # Restore: once the conflicting name is freed, the identical call succeeds -- proving the
    # rejection above was attributable to the name collision and nothing else about the request.
    cfn.delete_generated_template(GeneratedTemplateName=name_b)
    freed_code, message = _poll_until_notfound(cfn, name_b, timeout_s=120.0)
    assert freed_code == "GeneratedTemplateNotFound", (
        f"{name_b} should be gone after delete, but describing it returned {freed_code!r}"
    )
    # The message ends in a per-call request id: grade its stable prefix and suffix.
    assert message.startswith(f"Template with arn {name_b} does not exist (Service: ") and message.endswith(
        "; Proxy: null)"
    ), message

    _retry_rename_until_settled(cfn, name_a, name_b, timeout_s=60.0, interval_s=5.0)
    if not _wait_for_generated_template_terminal(ctx, name_b, timeout_s=180.0):
        raise AssertionError(
            f"restored generated template {name_b} never reached a terminal status in time",
        )


def _error(fn):
    """Return the (code, message) of the ClientError ``fn`` raises; a success is a defect."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be refused, but it succeeded and returned {result!r}")


def _delete_generated_template_quiet(cfn, name):
    from botocore.exceptions import ClientError

    try:
        cfn.delete_generated_template(GeneratedTemplateName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "GeneratedTemplateNotFound":
            raise


def _wait_for_generated_template_terminal(ctx, name, timeout_s=180.0, interval_s=5.0):
    cfn = ctx.client("cloudformation")
    deadline = time.monotonic() + timeout_s
    terminal = {"COMPLETE", "FAILED"}
    while time.monotonic() < deadline:
        resp = cfn.describe_generated_template(GeneratedTemplateName=name)
        if resp["Status"] in terminal:
            return True
        time.sleep(interval_s)
    return False


def _poll_until_notfound(cfn, name, timeout_s=120.0, interval_s=5.0):
    """Bounded wait for a deleted/renamed-away generated template to stop resolving.

    DeleteGeneratedTemplate (and the old identity after a rename) is asynchronous: a
    DescribeGeneratedTemplate can keep succeeding for a short window before the record is
    actually removed. Returns the error (code, message) once it stops resolving; RAISES if it still
    resolves at the deadline.
    """
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            cfn.describe_generated_template(GeneratedTemplateName=name)
        except ClientError as err:
            return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
        if time.monotonic() >= deadline:
            raise AssertionError(f"generated template {name} still resolves after {timeout_s}s")
        time.sleep(interval_s)


def _retry_rename_until_settled(cfn, old_name, new_name, timeout_s=60.0, interval_s=5.0):
    """Retry a rename that just had its conflict freed, in case the freed name takes a moment
    to become reusable. Returns once the rename succeeds; RAISES on any other refusal, or on
    AlreadyExistsException still answered at the deadline.
    """
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            cfn.update_generated_template(
                GeneratedTemplateName=old_name, NewGeneratedTemplateName=new_name
            )
            return
        except ClientError as err:
            code, message = err.response["Error"]["Code"], err.response["Error"].get("Message", "")
            conflict = code == "AlreadyExistsException" and message.startswith(
                f"Template with name {new_name} already exists. (Service: "
            )
            if not conflict or time.monotonic() >= deadline:
                raise AssertionError(
                    f"renaming {old_name} to {new_name} should succeed once {new_name} is freed, "
                    f"got {code!r}: {message!r}"
                ) from err
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
