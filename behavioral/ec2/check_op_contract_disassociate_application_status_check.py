"""op-contract-disassociate-application-status-check."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-disassociate-application-status-check"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DisassociateApplicationStatusCheck removes a tag-based association from an
    application status check; specifying both InstanceIds and TargetTagAssociation
    is rejected with InvalidParameterCombination per the documented contract."""
    ec2 = ctx.client("ec2")
    if not hasattr(ec2, "disassociate_application_status_check"):
        raise AssertionError("unreachable: application status checks API not present in this botocore version")

    resource_name = ctx.unique_name("sim2real-asc-")
    tag_key = ctx.unique_name("sim2real-asc-")
    tag_value = "v1"

    try:
        created = ec2.create_application_status_check(
            Protocol="http",
            Port=80,
            Path="/health",
            TagSpecifications=[
                {"ResourceType": "application-status-check", "Tags": [{"Key": "Name", "Value": resource_name}]}
            ],
        )
        check_id = created["ApplicationStatusCheck"]["ApplicationStatusCheckId"]
    except Exception as exc:  # noqa: BLE001 - feature may be gated/unsupported in some accounts
        raise AssertionError(f"unreachable: CreateApplicationStatusCheck unavailable ({exc})") from None

    ctx.on_cleanup(lambda: _safe(lambda: ec2.delete_application_status_check(ApplicationStatusCheckId=check_id)))

    ec2.associate_application_status_check(
        ApplicationStatusCheckId=check_id, TargetTagAssociations=[{"Key": tag_key, "Value": tag_value}]
    )

    # Error boundary: specifying both InstanceIds and TargetTagAssociations is invalid. A
    # malformed/nonexistent instance id short-circuits on InvalidInstanceID.Malformed before
    # the combination rule is ever evaluated, so this needs a genuinely valid instance id.
    instance_id = _launch_instance(ctx)
    code, message = _client_error(
        lambda: ec2.disassociate_application_status_check(
            ApplicationStatusCheckId=check_id,
            InstanceIds=[instance_id],
            TargetTagAssociations=[{"Key": tag_key, "Value": tag_value}],
        )
    )
    assert code == "InvalidParameterCombination", code
    assert message == "Only one of TargetTagAssociations or InstanceIds may be specified, not both", (
        f"unexpected InvalidParameterCombination message: {message!r}"
    )

    resp = ec2.disassociate_application_status_check(
        ApplicationStatusCheckId=check_id, TargetTagAssociations=[{"Key": tag_key, "Value": tag_value}]
    )
    successful = resp.get("SuccessfulResults", [])
    assert any(
        item.get("AssociationValue") == f"{tag_key}={tag_value}" for item in successful
    ), resp

    # Independent terminal read: the tag association must be gone at the describe endpoint, not
    # merely absent from the mutating call's own response.
    describe_resp = ec2.describe_application_status_check_associations(ApplicationStatusCheckIds=[check_id])
    remaining = _collect_strings(describe_resp)
    assert tag_key not in remaining, f"tag association still visible after disassociate: {describe_resp}"


def _collect_strings(obj) -> set:
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
    """Call fn(); return its error (code, message). An unexpected SUCCESS raises, because a
    target ACCEPTING a call real AWS refuses must not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _safe(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidApplicationStatusCheckId.NotFound":
            raise


def _default_vpc_subnet(ctx):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available in this account/region")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    if not subnets:
        raise AssertionError("shared network has no subnets")
    return subnets[0]["SubnetId"]


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
    subnet_id = _default_vpc_subnet(ctx)
    ami_id = _latest_al2023_ami(ec2)
    resp = ec2.run_instances(
        ImageId=ami_id,
        InstanceType="t3.micro",
        MinCount=1,
        MaxCount=1,
        SubnetId=subnet_id,
        TagSpecifications=[
            {"ResourceType": "instance", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-asc-inst-")}]}
        ],
    )
    instance_id = resp["Instances"][0]["InstanceId"]

    def _cleanup():
        ec2.terminate_instances(InstanceIds=[instance_id])
        ec2.get_waiter("instance_terminated").wait(InstanceIds=[instance_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    ctx.on_cleanup(_cleanup)
    ec2.get_waiter("instance_running").wait(InstanceIds=[instance_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    return instance_id


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
