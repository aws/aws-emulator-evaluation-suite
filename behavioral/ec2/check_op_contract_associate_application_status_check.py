"""op-contract-associate-application-status-check."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "op-contract-associate-application-status-check"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AssociateApplicationStatusCheck attaches a health check to an instance; specifying both
    InstanceIds and TargetTagAssociations together is rejected (InvalidParameterCombination)."""
    ec2 = ctx.client("ec2")

    try:
        instance_id, _subnet_id, _vpc_id = _launch_instance(ctx)
        check_id = ec2.create_application_status_check(Port=80, Protocol="http", Path="/")[
            "ApplicationStatusCheck"
        ]["ApplicationStatusCheckId"]
        ctx.on_cleanup(lambda: ec2.delete_application_status_check(ApplicationStatusCheckId=check_id))
    except Exception as exc:  # noqa: BLE001 - feature may not be available in this account/region yet
        raise AssertionError(f"application status checks unavailable: {exc}") from exc

    resp = ec2.associate_application_status_check(ApplicationStatusCheckId=check_id, InstanceIds=[instance_id])
    successes = resp.get("SuccessfulResults", [])
    assert len(successes) == 1, f"expected 1 successful association, got {resp}"
    assert successes[0]["AssociationValue"] == instance_id
    ctx.on_cleanup(
        lambda: ec2.disassociate_application_status_check(ApplicationStatusCheckId=check_id, InstanceIds=[instance_id])
    )

    # The association is applied asynchronously; describe can lag briefly behind the
    # associate call's SuccessfulResults, so poll a bounded window instead of reading once.
    # The instance id is searched for anywhere in the response rather than under a fixed key.
    def _describe_values():
        resp = ec2.describe_application_status_check_associations(ApplicationStatusCheckIds=[check_id])
        return resp, _collect_strings(resp)

    associations, values = _describe_values()
    deadline = time.monotonic() + 300
    while instance_id not in values and time.monotonic() < deadline:
        time.sleep(2)
        associations, values = _describe_values()
    assert instance_id in values, f"association not reflected: {associations}"

    code, message = _client_error(
        lambda: ec2.associate_application_status_check(
            ApplicationStatusCheckId=check_id,
            InstanceIds=[instance_id],
            TargetTagAssociations=[{"Key": "sim2real", "Value": "x"}],
        )
    )
    assert code == "InvalidParameterCombination", f"unexpected error code: {code}"
    expected = "Only one of TargetTagAssociations or InstanceIds may be specified, not both"
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _collect_strings(obj) -> set:
    """Recursively gather every string value nested anywhere in a response dict/list, so
    membership checks don't depend on guessing the exact (undocumented/shape-uncertain)
    field name a describe response uses to carry an id."""
    found: set = set()
    if isinstance(obj, dict):
        for v in obj.values():
            found |= _collect_strings(v)
    elif isinstance(obj, list):
        for v in obj:
            found |= _collect_strings(v)
    elif isinstance(obj, str):
        found.add(obj)
    return found


def _client_error(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises, because a target
    ACCEPTING a call real AWS refuses must not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"]
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _own_vpc_subnet(ctx):
    ec2 = ctx.client("ec2")
    vpc_id = ec2.create_vpc(CidrBlock="10.211.0.0/16")["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    az = ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}])[
        "AvailabilityZones"
    ][0]["ZoneName"]
    subnet_id = ec2.create_subnet(VpcId=vpc_id, CidrBlock="10.211.1.0/24", AvailabilityZone=az)["Subnet"][
        "SubnetId"
    ]
    ctx.on_cleanup(lambda: ec2.delete_subnet(SubnetId=subnet_id))
    return vpc_id, subnet_id


def _latest_al2023_ami(ec2):
    images = ec2.describe_images(
        Owners=["amazon"],
        Filters=[
            {"Name": "name", "Values": ["al2023-ami-*-x86_64"]},
            {"Name": "state", "Values": ["available"]},
        ],
    )["Images"]
    images.sort(key=lambda i: i["CreationDate"], reverse=True)
    return images[0]["ImageId"]


def _launch_instance(ctx):
    ec2 = ctx.client("ec2")
    vpc_id, subnet_id = _own_vpc_subnet(ctx)
    ami_id = _latest_al2023_ami(ec2)
    resp = ec2.run_instances(
        ImageId=ami_id,
        InstanceType="t3.micro",
        MinCount=1,
        MaxCount=1,
        SubnetId=subnet_id,
        TagSpecifications=[
            {"ResourceType": "instance", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-instance-")}]}
        ],
    )
    instance_id = resp["Instances"][0]["InstanceId"]

    def _cleanup():
        ec2.terminate_instances(InstanceIds=[instance_id])
        ec2.get_waiter("instance_terminated").wait(InstanceIds=[instance_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    ctx.on_cleanup(_cleanup)
    ec2.get_waiter("instance_running").wait(InstanceIds=[instance_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    return instance_id, subnet_id, vpc_id


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
