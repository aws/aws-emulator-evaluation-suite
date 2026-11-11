"""instance-metadata-options-http-tokens-roundtrip."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "instance-metadata-options-http-tokens-roundtrip"
GROUP = 'instance-lifecycle'
SERVICES = ['ec2']

ERR_INVALID_PARAM = 'InvalidParameterValue'
HOP_LIMIT_MAX = 64

def _code(exc):
    return exc.response.get("Error", {}).get("Code")


def _test_ami_id(ec2):
    """Return the newest x86_64 HVM EBS ImageId for RunInstances."""
    strict = [
        {"Name": "state", "Values": ["available"]},
        {"Name": "architecture", "Values": ["x86_64"]},
        {"Name": "virtualization-type", "Values": ["hvm"]},
        {"Name": "root-device-type", "Values": ["ebs"]},
    ]
    attempts = [
        {"Owners": ["amazon"], "Filters": strict + [{"Name": "name", "Values": ["al2023-ami-2023*-x86_64"]}]},
        {"Owners": ["amazon"], "Filters": strict + [{"Name": "name", "Values": ["amzn2-ami-hvm-*-x86_64-gp2"]}]},
        {"Owners": ["amazon"], "Filters": strict},
    ]
    for kw in attempts:
        try:
            images = ec2.describe_images(**kw).get("Images", [])
        except ClientError:
            continue
        if not images:
            continue
        images.sort(key=lambda i: i.get("CreationDate", ""), reverse=True)
        return images[0]["ImageId"]
    raise AssertionError("could not discover a usable test AMI")


def _get_default_subnet(ec2, *, ctx):
    try:
        subnets = ec2.describe_subnets(
            Filters=[{"Name": "subnet-id", "Values": ctx.network().subnet_ids}]
        ).get("Subnets", [])
    except ClientError as exc:
        raise AssertionError(f"could not list network subnets: {exc}")
    if not subnets:
        raise AssertionError("account has no network subnet for AZ-pinned launches")
    return subnets[0]["SubnetId"]


def _instance(ec2, instance_id):
    return ec2.describe_instances(InstanceIds=[instance_id])["Reservations"][0]["Instances"][0]


def _wait_instance_state(ec2, instance_id, state, timeout_s=240):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            resv = ec2.describe_instances(InstanceIds=[instance_id]).get("Reservations", [])
        except ClientError as exc:
            if _code(exc) == "InvalidInstanceID.NotFound":
                last = "__not_yet_visible__"
                time.sleep(3)
                continue
            raise
        last = resv[0]["Instances"][0]["State"]["Name"] if resv and resv[0].get("Instances") else "__none__"
        if last == state:
            return
        time.sleep(3)
    raise AssertionError(f"instance {instance_id} never reached {state!r} in {timeout_s}s (last {last!r})")


def _wait_metadata_applied(ec2, instance_id, *, hop_limit=None, http_tokens=None, timeout_s=180):
    """Poll until MetadataOptions is 'applied' with the just-written values.

    A stale 'applied' block still carrying the previous values must not satisfy the wait."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        opts = _instance(ec2, instance_id).get("MetadataOptions", {})
        last = opts
        if (
            opts.get("State") == "applied"
            and (hop_limit is None or opts.get("HttpPutResponseHopLimit") == hop_limit)
            and (http_tokens is None or opts.get("HttpTokens") == http_tokens)
        ):
            return opts
        time.sleep(3)
    raise AssertionError(
        f"instance {instance_id} MetadataOptions never settled to applied/"
        f"hop={hop_limit}/tokens={http_tokens} in {timeout_s}s (last {last!r})"
    )


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ModifyInstanceMetadataOptions round-trips HttpTokens=required and the hop limit, and a hop
    limit above the maximum of 64 is rejected without changing the applied value.
    """
    ec2 = ctx.client("ec2")
    subnet_id = _get_default_subnet(ec2, ctx=ctx)
    instance_id = ec2.run_instances(
        ImageId=_test_ami_id(ec2), InstanceType="t3.micro", MinCount=1, MaxCount=1,
        SubnetId=subnet_id,
        TagSpecifications=[{"ResourceType": "instance", "Tags": [{"Key": "sim2real", "Value": "1"}]}],
    )["Instances"][0]["InstanceId"]
    ctx.on_cleanup(lambda: ec2.terminate_instances(InstanceIds=[instance_id]))
    _wait_instance_state(ec2, instance_id, "running")

    launched = _instance(ec2, instance_id).get("MetadataOptions")
    assert launched, "a running instance must expose a MetadataOptions block"
    for field in ("State", "HttpTokens", "HttpPutResponseHopLimit", "HttpEndpoint"):
        assert field in launched, f"MetadataOptions is missing {field}: {launched}"

    written = ec2.modify_instance_metadata_options(
        InstanceId=instance_id,
        HttpTokens="required",
        HttpPutResponseHopLimit=3,
        HttpEndpoint="enabled",
    )["InstanceMetadataOptions"]
    assert written["HttpTokens"] == "required", (
        f"ModifyInstanceMetadataOptions must echo HttpTokens=required, got {written['HttpTokens']!r}"
    )
    assert written["State"] in ("pending", "applied"), (
        f"expected the options State to be pending|applied right after the write, got {written['State']!r}"
    )

    applied = _wait_metadata_applied(ec2, instance_id, hop_limit=3, http_tokens="required")
    assert applied["HttpTokens"] == "required", (
        f"DescribeInstances must reflect HttpTokens=required, got {applied['HttpTokens']!r}"
    )
    assert applied["HttpPutResponseHopLimit"] == 3, (
        f"expected HttpPutResponseHopLimit 3, got {applied['HttpPutResponseHopLimit']}"
    )
    assert applied["HttpEndpoint"] == "enabled", (
        f"expected HttpEndpoint enabled, got {applied['HttpEndpoint']!r}"
    )

    try:
        ec2.modify_instance_metadata_options(
            InstanceId=instance_id, HttpPutResponseHopLimit=HOP_LIMIT_MAX + 35
        )
    except ClientError as exc:
        assert _code(exc) == ERR_INVALID_PARAM, (
            f"expected {ERR_INVALID_PARAM} for HttpPutResponseHopLimit={HOP_LIMIT_MAX + 35}, got {_code(exc)}"
        )
        assert exc.response["Error"]["Message"] == (
            f"A value of '{HOP_LIMIT_MAX + 35}' is not valid for HttpPutResponseHopLimit. "
            f"Specify a value between 1 and {HOP_LIMIT_MAX} and try again."), exc.response["Error"]
    else:
        raise AssertionError(
            f"HttpPutResponseHopLimit={HOP_LIMIT_MAX + 35} is above the contract maximum "
            f"{HOP_LIMIT_MAX} and must be rejected, it succeeded"
        )

    unchanged = _instance(ec2, instance_id)["MetadataOptions"]
    assert unchanged["HttpPutResponseHopLimit"] == 3, (
        f"a rejected hop-limit write must leave the applied value at 3, got {unchanged['HttpPutResponseHopLimit']}"
    )
    assert unchanged["HttpTokens"] == "required", "a rejected write must not relax HttpTokens"

    ec2.modify_instance_metadata_options(
        InstanceId=instance_id, HttpPutResponseHopLimit=HOP_LIMIT_MAX
    )
    final = _wait_metadata_applied(ec2, instance_id, hop_limit=HOP_LIMIT_MAX, http_tokens="required")
    assert final["HttpPutResponseHopLimit"] == HOP_LIMIT_MAX, (
        f"the boundary hop limit {HOP_LIMIT_MAX} must be accepted, got {final['HttpPutResponseHopLimit']}"
    )
    assert final["HttpTokens"] == "required", (
        f"a hop-limit-only update must not relax the previously enforced HttpTokens, got {final['HttpTokens']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
