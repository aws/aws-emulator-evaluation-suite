"""op-contract-describe-image-references."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-describe-image-references"
GROUP = "error-semantics"
SERVICES = ["ec2"]
_DRY_RUN_MESSAGE = "Request would have succeeded, but DryRun flag is set."


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeImageReferences discovers a launch template that references an AMI, and
    DryRun short-circuits with DryRunOperation."""
    ec2 = ctx.client("ec2")
    ami_id = _find_al2023_ami(ctx)

    lt_name = ctx.unique_name("sim2real-lt-")
    lt = ec2.create_launch_template(
        LaunchTemplateName=lt_name,
        LaunchTemplateData={"ImageId": ami_id},
        TagSpecifications=[_tag_spec(ctx, "launch-template")],
    )["LaunchTemplate"]
    lt_id = lt["LaunchTemplateId"]
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateId=lt_id))

    def _matching(refs):
        return [
            r
            for r in refs
            if r.get("ImageId") == ami_id
            and r.get("ResourceType") == "ec2:LaunchTemplate"
            and lt_id in r.get("Arn", "")
        ]

    references = _poll_until(
        lambda: ec2.describe_image_references(
            ImageIds=[ami_id], ResourceTypes=[{"ResourceType": "ec2:LaunchTemplate"}]
        )["ImageReferences"],
        lambda refs: bool(_matching(refs)),
        timeout_s=60.0,
        interval_s=3.0,
    )
    matched = _matching(references)
    assert matched, f"expected launch template {lt_id} to reference image {ami_id}, got {references}"

    # Error boundary: DryRun short-circuits before the check is performed.
    code, message = _error(
        lambda: ec2.describe_image_references(ImageIds=[ami_id], IncludeAllResourceTypes=True, DryRun=True)
    )
    assert code == "DryRunOperation", f"expected DryRunOperation, got {code}"
    assert message == _DRY_RUN_MESSAGE, f"expected message {_DRY_RUN_MESSAGE!r}, got {message!r}"


def _tag_spec(ctx, resource_type):
    return {
        "ResourceType": resource_type,
        "Tags": [{"Key": "Name", "Value": ctx.unique_name(f"sim2real-behav-{resource_type}-")}],
    }


def _error(fn):
    """Return fn()'s (code, message); a success raises, never reading as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err["Message"]
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last}")


def _find_al2023_ami(ctx) -> str:
    ec2 = ctx.client("ec2")
    resp = ec2.describe_images(
        Owners=["amazon"],
        Filters=[
            {"Name": "name", "Values": ["al2023-ami-*-x86_64"]},
            {"Name": "state", "Values": ["available"]},
        ],
    )
    images = resp.get("Images", [])
    if not images:
        raise AssertionError("no amazon-owned al2023 AMI visible in this account/region")
    images.sort(key=lambda i: i.get("CreationDate", ""), reverse=True)
    return images[0]["ImageId"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
