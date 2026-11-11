"""instance-metadata-defaults-optional-overrides-ami-imds-support-precedence."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "instance-metadata-defaults-optional-overrides-ami-imds-support-precedence"
GROUP = "data-plane"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:ec2-instance-metadata-defaults")
def run(ctx) -> None:
    """An instance launched without MetadataOptions inherits the account default HttpTokens
    'optional' even from an AMI whose ImdsSupport is 'v2.0', but with the account default
    'no-preference' it inherits the AMI's 'v2.0' as HttpTokens 'required' instead."""
    ec2 = ctx.client("ec2")
    net = ctx.network()

    ami_id, imds_support = _latest_al2023_ami(ec2)
    assert imds_support == "v2.0", (
        f"this check proves account-default precedence over an AMI ImdsSupport default of "
        f"'v2.0', but the latest Amazon Linux 2023 AMI reports ImdsSupport={imds_support!r}"
    )

    before = ec2.get_instance_metadata_defaults().get("AccountLevel") or {}
    original_http_tokens = before.get("HttpTokens", "no-preference")
    original_hop_limit = before.get("HttpPutResponseHopLimit") or -1
    original_http_endpoint = before.get("HttpEndpoint", "no-preference")
    original_metadata_tags = before.get("InstanceMetadataTags", "no-preference")

    def _restore():
        ec2.modify_instance_metadata_defaults(
            HttpTokens=original_http_tokens,
            HttpPutResponseHopLimit=original_hop_limit,
            HttpEndpoint=original_http_endpoint,
            InstanceMetadataTags=original_metadata_tags,
        )

    ec2.modify_instance_metadata_defaults(
        HttpTokens="optional", HttpPutResponseHopLimit=-1,
        HttpEndpoint="no-preference", InstanceMetadataTags="no-preference",
    )
    ctx.on_cleanup(_restore)
    after = ec2.get_instance_metadata_defaults()["AccountLevel"]
    assert after["HttpTokens"] == "optional", after

    instance_a = _run_instance(ctx, ec2, net, ami_id)
    ctx.on_cleanup(lambda: _terminate(ec2, instance_a))
    described_a = _wait_running(ec2, instance_a)
    assert described_a["MetadataOptions"]["HttpTokens"] == "optional", (
        f"account default HttpTokens='optional' must be inherited over the AMI's ImdsSupport "
        f"default, got MetadataOptions={described_a['MetadataOptions']!r}"
    )

    ec2.modify_instance_metadata_defaults(
        HttpTokens="no-preference", HttpPutResponseHopLimit=-1,
        HttpEndpoint="no-preference", InstanceMetadataTags="no-preference",
    )
    after2 = ec2.get_instance_metadata_defaults()["AccountLevel"]
    # AWS omits HttpTokens entirely once it is set back to 'no-preference' rather than echoing
    # the literal value.
    assert after2.get("HttpTokens", "no-preference") == "no-preference", after2

    instance_b = _run_instance(ctx, ec2, net, ami_id)
    ctx.on_cleanup(lambda: _terminate(ec2, instance_b))
    described_b = _wait_running(ec2, instance_b)
    assert described_b["MetadataOptions"]["HttpTokens"] == "required", (
        f"account default HttpTokens='no-preference' must fall through to the AMI's "
        f"ImdsSupport='v2.0' default (HttpTokens 'required'), got "
        f"MetadataOptions={described_b['MetadataOptions']!r}"
    )


def _run_instance(ctx, ec2, net, ami_id: str) -> str:
    resp = ec2.run_instances(
        ImageId=ami_id,
        InstanceType="t3.micro",
        MinCount=1,
        MaxCount=1,
        TagSpecifications=[
            {
                "ResourceType": "instance",
                "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-i-")}],
            }
        ],
        SubnetId=net.subnet_ids[0],
    )
    return resp["Instances"][0]["InstanceId"]


def _wait_running(ec2, instance_id: str) -> dict:
    ec2.get_waiter("instance_running").wait(
        InstanceIds=[instance_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300}
    )
    return ec2.describe_instances(InstanceIds=[instance_id])["Reservations"][0]["Instances"][0]


def _terminate(ec2, instance_id: str) -> None:
    try:
        ec2.terminate_instances(InstanceIds=[instance_id])
        ec2.get_waiter("instance_terminated").wait(
            InstanceIds=[instance_id], WaiterConfig={"Delay": 2, "MaxAttempts": 150}
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidInstanceID.NotFound":
            raise


def _latest_al2023_ami(ec2) -> tuple[str, str | None]:
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
    latest = images[0]
    return latest["ImageId"], latest.get("ImdsSupport")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
