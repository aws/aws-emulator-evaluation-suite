"""create-fleet-contract."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-fleet-contract"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateFleet under DryRun answers DryRunOperation for a request on a real launch template, while a real call
    naming an unallocated launch template id is refused with InvalidLaunchTemplateId.Malformed, each with its
    exact message, and creates no fleet.
    """
    ec2 = ctx.client("ec2")
    ami_id = _latest_al2023_ami(ctx)

    lt_name = ctx.unique_name("sim2real-behav-lt-")
    launch_template = ec2.create_launch_template(
        LaunchTemplateName=lt_name,
        LaunchTemplateData={"ImageId": ami_id, "InstanceType": "t3.micro"},
        TagSpecifications=[_tag_spec(ctx, "launch-template")],
    )["LaunchTemplate"]
    lt_id = launch_template["LaunchTemplateId"]
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateId=lt_id))

    good_kwargs = dict(
        LaunchTemplateConfigs=[
            {"LaunchTemplateSpecification": {"LaunchTemplateId": lt_id, "Version": "$Latest"}}
        ],
        TargetCapacitySpecification={"TotalTargetCapacity": 1, "DefaultTargetCapacityType": "on-demand"},
        Type="instant",
    )
    code, message = _reject(ctx, ec2, lambda: ec2.create_fleet(DryRun=True, **good_kwargs))
    assert code == "DryRunOperation", (
        f"expected DryRunOperation for a well-formed fleet request, got {code!r} ({message})"
    )
    assert message == "Request would have succeeded, but DryRun flag is set.", f"unexpected error message {message!r}"

    # DryRun checks permissions only and does not resolve the launch template, so the bogus template
    # is sent without DryRun; it is refused before anything launches, and a made-up 17-character id is
    # reported as malformed rather than not found.
    bad_spec = _tag_spec(ctx, "fleet")
    bad_name = bad_spec["Tags"][0]["Value"]
    bad_kwargs = dict(good_kwargs, TagSpecifications=[bad_spec])
    bad_kwargs["LaunchTemplateConfigs"] = [
        {"LaunchTemplateSpecification": {"LaunchTemplateId": "lt-0123456789abcdef0", "Version": "$Latest"}}
    ]
    code2, message2 = _reject(ctx, ec2, lambda: ec2.create_fleet(**bad_kwargs))
    assert code2 == "InvalidLaunchTemplateId.Malformed", (
        f"expected InvalidLaunchTemplateId.Malformed, got {code2!r} ({message2})"
    )
    assert message2 == "The specified launch template ID 'lt-0123456789abcdef0' is malformed.", f"unexpected error message {message2!r}"

    created = _fleet_ids(ec2, bad_name)
    assert created == set(), f"the rejected CreateFleet call created a fleet anyway: {created!r}"


def _reject(ctx, ec2, fn):
    """Call fn(); return its botocore (Error.Code, Error.Message). An unexpected SUCCESS raises
    rather than returning a falsy sentinel, because an over-permissive target accepting a call real
    AWS refuses is the strongest signal available. If the call did create a fleet, register it for
    cleanup before raising."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    fleet_id = result.get("FleetId")
    if fleet_id:
        ctx.on_cleanup(lambda: ec2.delete_fleets(FleetIds=[fleet_id], TerminateInstances=True))
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _fleet_ids(ec2, name):
    """Ids of the fleets tagged Name=name, read through all pages."""
    ids = set()
    token = None
    while True:
        page = ec2.describe_fleets(**({"NextToken": token} if token else {}))
        ids.update(
            f["FleetId"]
            for f in page["Fleets"]
            if {"Key": "Name", "Value": name} in f.get("Tags", [])
        )
        token = page.get("NextToken")
        if not token:
            return ids


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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
