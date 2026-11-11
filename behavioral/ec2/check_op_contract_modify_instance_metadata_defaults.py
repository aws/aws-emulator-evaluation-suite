"""op-contract-modify-instance-metadata-defaults."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-modify-instance-metadata-defaults"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:ec2-instance-metadata-defaults")
def run(ctx) -> None:
    """ModifyInstanceMetadataDefaults sets HttpTokens=required and hop limit 2, and an instance launched
    without MetadataOptions inherits both; a hop limit above 64 fails with InvalidParameterValue and its
    exact message and leaves the default at 2."""
    ec2 = ctx.client("ec2")

    before = ec2.get_instance_metadata_defaults().get("AccountLevel") or {}

    def _restore():
        ec2.modify_instance_metadata_defaults(
            HttpTokens=before.get("HttpTokens", "no-preference"),
            HttpPutResponseHopLimit=before.get("HttpPutResponseHopLimit") or -1,
            HttpEndpoint=before.get("HttpEndpoint", "no-preference"),
            InstanceMetadataTags=before.get("InstanceMetadataTags", "no-preference"),
        )

    ctx.on_cleanup(_restore)

    ec2.modify_instance_metadata_defaults(
        HttpTokens="required", HttpEndpoint="enabled", HttpPutResponseHopLimit=2
    )
    after = ec2.get_instance_metadata_defaults()["AccountLevel"]
    assert after["HttpTokens"] == "required", after
    assert after["HttpEndpoint"] == "enabled", after
    assert after["HttpPutResponseHopLimit"] == 2, after

    instance_id = _run_instance(ctx, ec2, "t3.micro")
    ctx.on_cleanup(lambda: _terminate(ec2, instance_id))
    ec2.get_waiter("instance_running").wait(InstanceIds=[instance_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    described = ec2.describe_instances(InstanceIds=[instance_id])["Reservations"][0]["Instances"][0]
    metadata_opts = described["MetadataOptions"]
    assert metadata_opts["HttpTokens"] == "required", metadata_opts
    assert metadata_opts["HttpPutResponseHopLimit"] == 2, metadata_opts

    # Range boundary: HttpPutResponseHopLimit must be between 1 and 64 (or -1 for
    # no-preference); 100 is out of range.
    code, message = _error(
        lambda: ec2.modify_instance_metadata_defaults(HttpPutResponseHopLimit=100)
    )
    assert code == "InvalidParameterValue", f"expected InvalidParameterValue, got {code}"
    assert message == "Invalid value for HttpPutResponseHopLimit. Expecting 1-64, or -1 for no-preference.", message

    # Effect absent: the rejected call must not have overwritten the prior stored value.
    after_reject = ec2.get_instance_metadata_defaults()["AccountLevel"]
    assert after_reject["HttpPutResponseHopLimit"] == 2, (
        f"rejected ModifyInstanceMetadataDefaults call still changed the account default: {after_reject}"
    )


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. A SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        error = exc.response["Error"]
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _latest_al2023_ami(ec2) -> str:
    images = ec2.describe_images(
        Owners=["amazon"],
        Filters=[
            {"Name": "name", "Values": ["al2023-ami-*-x86_64"]},
            {"Name": "state", "Values": ["available"]},
        ],
    )["Images"]
    if not images:
        raise AssertionError("no amazon-owned al2023 AMIs found in this region")
    images.sort(key=lambda i: i["CreationDate"], reverse=True)
    return images[0]["ImageId"]


def _run_instance(ctx, ec2, instance_type: str) -> str:
    ami_id = _latest_al2023_ami(ec2)
    resp = ec2.run_instances(
        ImageId=ami_id,
        InstanceType=instance_type,
        MinCount=1,
        MaxCount=1,
        TagSpecifications=[
            {
                "ResourceType": "instance",
                "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-i-")}],
            }
        ],
        SubnetId=ctx.network().subnet_ids[0],
    )
    return resp["Instances"][0]["InstanceId"]


def _terminate(ec2, instance_id: str) -> None:
    try:
        ec2.terminate_instances(InstanceIds=[instance_id])
        ec2.get_waiter("instance_terminated").wait(
            InstanceIds=[instance_id], WaiterConfig={"Delay": 2, "MaxAttempts": 150}
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidInstanceID.NotFound":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
