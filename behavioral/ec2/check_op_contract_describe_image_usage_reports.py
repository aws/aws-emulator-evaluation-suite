"""op-contract-describe-image-usage-reports."""
from __future__ import annotations

import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-describe-image-usage-reports"
GROUP = "error-semantics"
SERVICES = ["ec2"]
_DRY_RUN_MESSAGE = "Request would have succeeded, but DryRun flag is set."


@tags(
    "axis:rejection",
    "cap:c1",
    "cap:c4",
    "concern:negative-classes",
    "concern:representation",
    "plane:control",
)
def run(ctx) -> None:
    """DescribeImageUsageReports returns a well-formed report set, its 'state' filter
    actually discriminates a real report's own state from the state it is NOT in, an
    unknown filter name is rejected, and DryRun short-circuits with DryRunOperation."""
    ec2 = ctx.client("ec2")

    resp = ec2.describe_image_usage_reports()
    reports = resp.get("ImageUsageReports")
    assert isinstance(reports, list), f"expected ImageUsageReports to be a list, got {reports!r}"
    assert resp.get("NextToken") in (None, ""), f"unexpected NextToken {resp.get('NextToken')!r}"

    report_id, actual_state = _create_report(ctx, ec2)

    matching = ec2.describe_image_usage_reports(Filters=[{"Name": "state", "Values": [actual_state]}])[
        "ImageUsageReports"
    ]
    assert all(r["State"] == actual_state for r in matching), (
        f"state={actual_state!r} filter returned a report in a different state: {matching!r}"
    )
    assert any(r["ReportId"] == report_id for r in matching), (
        f"expected report {report_id} (state={actual_state!r}) to appear when filtered by its own state"
    )

    # The filter must also EXCLUDE: prove discrimination, not just non-empty membership.
    other_state = "available" if actual_state == "pending" else "pending"
    mismatched = ec2.describe_image_usage_reports(Filters=[{"Name": "state", "Values": [other_state]}])[
        "ImageUsageReports"
    ]
    assert not any(r["ReportId"] == report_id for r in mismatched), (
        f"report {report_id} (state={actual_state!r}) leaked into the state={other_state!r} filter"
    )

    # Error boundary: an unknown filter name is rejected server-side.
    code, message = _error(
        lambda: ec2.describe_image_usage_reports(Filters=[{"Name": "sim2real-bogus-filter", "Values": ["x"]}])
    )
    assert code == "InvalidFilter", f"expected InvalidFilter, got {code}"
    expected = "An invalid filter name was provided. Remove the filter and try again."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # DryRun short-circuits before the check is performed.
    dry_code, dry_message = _error(lambda: ec2.describe_image_usage_reports(DryRun=True))
    assert dry_code == "DryRunOperation", f"expected DryRunOperation, got {dry_code}"
    assert dry_message == _DRY_RUN_MESSAGE, f"expected message {_DRY_RUN_MESSAGE!r}, got {dry_message!r}"


def _create_report(ctx, ec2):
    """Provision a real, owned image and a real ImageUsageReport scoped to it, so the 'state' filter
    above is exercised against a report that actually exists rather than trivially satisfied by an
    empty account.
    """
    instance_id = _run_tagged_instance(ctx)
    image_id = ec2.create_image(
        InstanceId=instance_id, Name=ctx.unique_name("sim2real-behav-diur-ami-"), NoReboot=True
    )["ImageId"]

    def _cleanup_image():
        try:
            ec2.deregister_image(ImageId=image_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in (
                "InvalidAMIID.NotFound",
                "InvalidAMIID.Unavailable",
            ):
                raise
        # CreateImage's snapshots are found by the image id in their description at teardown
        # time: the image's own block device mappings are empty while it is still pending.
        snapshots = ec2.describe_snapshots(
            OwnerIds=["self"], Filters=[{"Name": "description", "Values": [f"*{image_id}*"]}]
        )["Snapshots"]
        for snapshot in snapshots:
            _delete_snapshot(ec2, snapshot["SnapshotId"])

    ctx.on_cleanup(_cleanup_image)

    resp, _resource_type_value = _create_image_usage_report(ec2, image_id)
    report_id = resp["ReportId"]
    assert report_id, f"expected a ReportId, got {resp!r}"
    ctx.on_cleanup(lambda: _ignore(lambda: ec2.delete_image_usage_report(ReportId=report_id)))

    described = ec2.describe_image_usage_reports(ReportIds=[report_id])["ImageUsageReports"]
    assert described, f"expected report {report_id} to be visible via DescribeImageUsageReports"
    state = described[0]["State"]
    # A freshly created report is always "pending" or "available", never
    # a third value at creation time.
    assert state in ("pending", "available"), f"unexpected report state {state!r}"
    return report_id, state


def _create_image_usage_report_kwargs(ec2, image_id, resource_type_value="instance"):
    """Build a well-formed CreateImageUsageReport request from the installed botocore
    service model rather than a hand-guessed shape, because this newer, less-common EC2
    API's parameter names/nesting drift out of sync with a hardcoded guess and raise a
    client-side ParamValidationError before the request is ever sent. The model does not
    mark the ResourceTypes member as required even though the live API rejects a request
    without one (MissingParameter) — so every resource-type-ish member (matched by
    substring, case-insensitively, since the model's exact member name varies) is always
    included, at every nesting level, alongside whatever the model does mark required.
    """
    op_model = ec2.meta.service_model.operation_model("CreateImageUsageReport")
    input_shape = op_model.input_shape
    kwargs = {"ImageId": image_id}
    resource_types_members = [name for name in input_shape.members if "resourcetype" in name.lower()]
    names_to_fill = set(input_shape.required_members)
    names_to_fill.update(resource_types_members)
    for name in names_to_fill:
        if name == "ImageId":
            continue
        in_resource_type_branch = name in resource_types_members
        kwargs[name] = _placeholder_value(input_shape.members[name], in_resource_type_branch, resource_type_value)
    return kwargs


def _placeholder_value(shape, in_resource_type_branch=False, resource_type_value="instance"):
    if shape.type_name == "list":
        return [_placeholder_value(shape.member, in_resource_type_branch, resource_type_value)]
    if shape.type_name == "structure":
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
    """The installed botocore model exposes no enum for the ResourceTypes token, so the
    only reliable way to learn a valid one is to try candidates against the live API.
    Harvested documentation tokens are tried first (AWS often spells valid values out in
    free-text docs even without a formal enum trait), then a static list of real,
    existing EC2 resource-type tokens (AWS rejects plausible-looking invented tokens
    uniformly). Only continue on InvalidParameterValue (a bad
    token); any other error is a real failure and must propagate.
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
    """Walk every resource-type-ish member of the request shape (including nested ones)
    and pull candidate tokens out of their documentation text."""
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
    valid_values_pattern = re.compile(r"[Vv]alid values?(?: are| include)?:?\s*([^.<]+)")
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


def _error(fn):
    """Return fn()'s (code, message); a success raises, never reading as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err["Message"]
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _ignore(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidImageUsageReportId.NotFound":
            raise


def _delete_snapshot(ec2, snapshot_id, timeout_s=300.0, interval_s=10.0):
    """Delete an AMI's snapshot, retrying while the just-deregistered image still holds it."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ec2.delete_snapshot(SnapshotId=snapshot_id)
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "InvalidSnapshot.NotFound":
                return
            if time.monotonic() >= deadline:
                raise
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
