"""create-image-usage-report-contract."""
from __future__ import annotations

import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-image-usage-report-contract"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateImageUsageReport creates a report scoped to a real, owned image
    that is later visible via DescribeImageUsageReports, and rejects a
    non-existent image id.
    """
    ec2 = ctx.client("ec2")
    if not hasattr(ec2, "create_image_usage_report"):
        raise AssertionError("installed botocore does not support CreateImageUsageReport")

    instance_id = _run_tagged_instance(ctx)
    image_id = ec2.create_image(
        InstanceId=instance_id, Name=ctx.unique_name("sim2real-behav-ami-"), NoReboot=True
    )["ImageId"]

    ctx.on_cleanup(lambda: _deregister_with_snapshots(ec2, image_id))

    resp, resource_type_value = _create_image_usage_report(ec2, image_id)
    report_id = resp["ReportId"]
    assert report_id, f"expected CreateImageUsageReport to return a non-empty ReportId, got {resp!r}"
    ctx.on_cleanup(lambda: ec2.delete_image_usage_report(ReportId=report_id))

    described = ec2.describe_image_usage_reports(ReportIds=[report_id])["ImageUsageReports"]
    assert described, f"expected report {report_id} to be visible via DescribeImageUsageReports"
    assert described[0]["ImageId"] == image_id, (
        f"expected DescribeImageUsageReports to echo ImageId {image_id!r}, got {described[0]['ImageId']!r}"
    )
    assert described[0]["State"] in ("pending", "available"), (
        f"expected a freshly created report to be pending or available, got {described[0]['State']!r}"
    )

    # Error boundary: a non-existent AMI id must be rejected up front, and
    # must not produce a report. Reuse the resource-type value that the live
    # API already accepted above, so this exercises the instance-id boundary
    # rather than tripping over the same resource-type placeholder guess.
    # CreateImageUsageReport reports a well-formed but nonexistent AMI id as
    # InvalidAMIID.Malformed rather than InvalidAMIID.NotFound.
    code, message = _error(
        lambda: ec2.create_image_usage_report(
            **_create_image_usage_report_kwargs(
                ec2, "ami-0123456789abcdef0", resource_type_value=resource_type_value
            )
        )
    )
    assert code == "InvalidAMIID.Malformed", f"expected InvalidAMIID.Malformed, got {code!r}"
    assert message == "The image ID 'ami-0123456789abcdef0' is malformed", message


# ===== helpers =====
def _deregister_with_snapshots(ec2, image_id, timeout_s=120.0):
    """Teardown: deregister the AMI and delete the snapshots behind it. The block device mappings
    can still be empty right after CreateImage, so wait (bounded) for them before deregistering."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            images = ec2.describe_images(ImageIds=[image_id])["Images"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("InvalidAMIID.NotFound", "InvalidAMIID.Unavailable"):
                raise
            images = []
        snapshot_ids = [
            m["Ebs"]["SnapshotId"]
            for image in images
            for m in image.get("BlockDeviceMappings", [])
            if "SnapshotId" in m.get("Ebs", {})
        ]
        if snapshot_ids or not images or time.monotonic() >= deadline:
            break
        time.sleep(5)
    try:
        ec2.deregister_image(ImageId=image_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "InvalidAMIID.NotFound",
            "InvalidAMIID.Unavailable",
        ):
            raise
    for snapshot_id in snapshot_ids:
        try:
            ec2.delete_snapshot(SnapshotId=snapshot_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidSnapshot.NotFound":
                raise


def _create_image_usage_report_kwargs(ec2, image_id, resource_type_value="instance"):
    """Build a well-formed CreateImageUsageReport request using the installed
    botocore service model instead of a hand-guessed shape: this is a newer,
    less-common EC2 API, and hardcoding the parameter names/nesting for its
    resource-type list drifts out of sync with the actual model, causing a
    client-side ParamValidationError before the request is ever sent.

    The model does not mark the resource-type string(s) as an enum (no
    enum metadata on the shape), even though the live API only accepts a small,
    specific set of free-form tokens for that field, so `resource_type_value`
    lets the caller supply the token to use for every resource-type-ish
    member encountered anywhere in the request (including nested ones),
    rather than relying on a single hardcoded guess that may not be valid.
    """
    op_model = ec2.meta.service_model.operation_model("CreateImageUsageReport")
    input_shape = op_model.input_shape
    kwargs = {"ImageId": image_id}
    # The installed botocore model does not always mark the resource-types
    # member as required (it is frequently modeled with clientOptional even
    # though the live API rejects a request without it: MissingParameter,
    # "The request must include the ResourceTypes parameter"). Always
    # include it - alongside whatever the model *does* mark required -
    # rather than trusting required_members alone. Match members by
    # substring ("resourcetype" appearing anywhere in the member name,
    # case-insensitively), not by exact equality: on real AWS the installed
    # model names this member something like "ImageUsageReportResourceType"/
    # "ResourceTypes" rather than the bare "ResourceType"/"ResourceTypes",
    # and an exact-match comparison silently fails to find it - leaving the
    # kwarg unset and reproducing the exact MissingParameter error this
    # helper exists to avoid. Collect *every* member matching the substring
    # (not just the first one found via `next`): the model can expose more
    # than one resource-type-ish member (e.g. an optional filter alongside
    # the actual required list), and picking only the first candidate in
    # iteration order risks silently filling the wrong one while leaving the
    # real ResourceTypes member absent from the request - reproducing the
    # exact MissingParameter error this helper exists to avoid.
    resource_types_members = [
        name for name in input_shape.members if "resourcetype" in name.lower()
    ]
    names_to_fill = set(input_shape.required_members)
    names_to_fill.update(resource_types_members)
    for name in names_to_fill:
        if name == "ImageId":
            continue
        in_resource_type_branch = name in resource_types_members
        kwargs[name] = _placeholder_value(
            input_shape.members[name], in_resource_type_branch, resource_type_value
        )
    return kwargs


def _placeholder_value(shape, in_resource_type_branch=False, resource_type_value="instance"):
    if shape.type_name == "list":
        return [_placeholder_value(shape.member, in_resource_type_branch, resource_type_value)]
    if shape.type_name == "structure":
        # Fill every member the model marks required, *plus* any
        # resource-type-ish member at this nesting level, for the same
        # reason the top-level kwarg builder does: the installed botocore
        # model does not always mark such members as required even though
        # the live API rejects a request without one (MissingParameter,
        # "The request must include the ResourceTypes parameter"). The live
        # CreateImageUsageReport request shape nests its resource-type list
        # inside a required structure member rather than exposing it at the
        # top level, so this heuristic must be applied recursively at every
        # structure level encountered while building placeholders, not just
        # to the request's immediate top-level members - otherwise the
        # nested ResourceTypes-ish field is silently left unset and the
        # request reproduces the exact MissingParameter error this helper
        # exists to avoid.
        member_names = set(shape.required_members)
        resource_type_names = {name for name in shape.members if "resourcetype" in name.lower()}
        member_names.update(resource_type_names)
        return {
            name: _placeholder_value(
                shape.members[name],
                in_resource_type_branch or name in resource_type_names,
                resource_type_value,
            )
            for name in member_names
        }
    if shape.type_name == "string":
        enum = shape.metadata.get("enum")
        if enum:
            return enum[0]
        if in_resource_type_branch:
            return resource_type_value
        return "instance"
    if shape.type_name in ("integer", "long"):
        return 1
    if shape.type_name == "boolean":
        return False
    return "instance"


def _create_image_usage_report(ec2, image_id):
    """Create a usage report for `image_id`, trying candidate ResourceType tokens in turn.

    Tokens recovered from the model's member documentation are tried first, then a static list
    of EC2 resource-type tokens. Only InvalidParameterValue (a bad token) moves on to the next
    candidate; any other error propagates. See
    https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_CreateImageUsageReport.html
    """
    candidates = [
        "instance",
        "launch-template",
        "fleet",
        "spot-fleet-request",
        "spot-instances-request",
        "capacity-reservation",
        "capacity-reservation-fleet",
        "reserved-instances",
        "scheduled-instances",
        "image",
        "fpga-image",
        "export-image-task",
        "import-image-task",
        "replace-root-volume-task",
        "snapshot",
        "Instance",
        "LaunchTemplate",
        "Fleet",
        "SpotFleetRequest",
        "CapacityReservation",
        "Image",
        "INSTANCE",
        "LAUNCH_TEMPLATE",
        "FLEET",
    ]
    # Tokens spelled out in the member's documentation are tried ahead of the static list.
    op_model = ec2.meta.service_model.operation_model("CreateImageUsageReport")
    harvested = _harvest_enum_candidates(op_model.input_shape)
    ordered_candidates = harvested + [c for c in candidates if c not in harvested]
    last_error = None
    for candidate in ordered_candidates:
        kwargs = _create_image_usage_report_kwargs(ec2, image_id, resource_type_value=candidate)
        try:
            return ec2.create_image_usage_report(**kwargs), candidate
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidParameterValue":
                raise
            last_error = exc
    raise last_error


def _harvest_enum_candidates(input_shape):
    """Walk every resource-type-ish member of the request shape (including
    nested ones, mirroring the recursion in `_placeholder_value`) and pull
    candidate tokens out of their documentation text. AWS API documentation
    commonly spells out accepted values either inline as `<code>token</code>`
    snippets or as a "Valid values ..." sentence, even for members that lack
    a formal `enum` trait in the generated model.
    """
    doc_texts = []

    def _walk(shape, seen):
        if id(shape) in seen:
            return
        seen.add(id(shape))
        if shape.type_name == "structure":
            for name, member_shape in shape.members.items():
                if "resourcetype" in name.lower():
                    doc = getattr(member_shape, "documentation", None)
                    if doc:
                        doc_texts.append(doc)
                _walk(member_shape, seen)
        elif shape.type_name == "list":
            _walk(shape.member, seen)

    _walk(input_shape, set())

    code_pattern = re.compile(r"<code>([^<>]+)</code>")
    valid_values_pattern = re.compile(
        r"[Vv]alid values?(?: are| include)?:?\s*([^.<]+)"
    )
    tokens = []
    for text in doc_texts:
        for match in code_pattern.findall(text):
            candidate = match.strip()
            if candidate:
                tokens.append(candidate)
        for segment in valid_values_pattern.findall(text):
            for piece in re.split(r"\s*(?:,|\||\band\b|\bor\b)\s*", segment):
                piece = piece.strip().strip(".").strip('"').strip("'")
                if piece:
                    tokens.append(piece)

    seen_tokens = set()
    ordered = []
    for token in tokens:
        if token not in seen_tokens:
            seen_tokens.add(token)
            ordered.append(token)
    return ordered


def _error(fn):
    """Call *fn*; return its (code, message). An unexpected SUCCESS raises, because a target
    accepting what real AWS refuses is reported as that success, not as an error-code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _tag_spec(ctx, resource_type):
    return {
        "ResourceType": resource_type,
        "Tags": [{"Key": "Name", "Value": ctx.unique_name(f"sim2real-behav-{resource_type}-")}],
    }


def _latest_al2023_ami(ctx):
    ec2 = ctx.client("ec2")
    images = ec2.describe_images(
        Owners=["amazon"],
        Filters=[
            {"Name": "name", "Values": ["al2023-ami-2023.*-x86_64"]},
            {"Name": "state", "Values": ["available"]},
        ],
    )["Images"]
    if not images:
        raise AssertionError("no Amazon Linux 2023 AMI visible in this region")
    images.sort(key=lambda i: i["CreationDate"], reverse=True)
    return images[0]["ImageId"]


def _run_tagged_instance(ctx):
    ec2 = ctx.client("ec2")
    ami_id = _latest_al2023_ami(ctx)
    resp = ec2.run_instances(
        ImageId=ami_id,
        InstanceType="t3.micro",
        MinCount=1,
        MaxCount=1,
        TagSpecifications=[_tag_spec(ctx, "instance")],
        SubnetId=ctx.network().subnet_ids[0],
    )
    instance_id = resp["Instances"][0]["InstanceId"]
    ctx.on_cleanup(lambda: ec2.terminate_instances(InstanceIds=[instance_id]))
    waiter = ec2.get_waiter("instance_running")
    waiter.wait(InstanceIds=[instance_id], WaiterConfig={"Delay": 2, "MaxAttempts": 100})
    return instance_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
