"""ca-enrollment-policy-server-enforced-toggle."""
from __future__ import annotations

import time
import uuid

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "ca-enrollment-policy-server-enforced-toggle"
GROUP = "server-side"
SERVICES = ["ds"]

_PASSWORD = "Sim2Real-Caenroll-2024!"


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Enable/DisableCAEnrollmentPolicy with a nonexistent PCA connector ARN fail synchronously with
    EntityDoesNotExistException naming the connector or the directory, leave the policy status and
    connector ARN unchanged, and the directory still accepts an unrelated tag mutation."""
    ds = ctx.client("ds")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    # A real connector needs a billed AWS Private CA, so a well-formed nonexistent ARN is used.
    fake_connector_arn = f"arn:aws:pca-connector-ad:{ctx.region}:{account_id}:connector/{uuid.uuid4()}"

    # One teardown deadline per run, shared by every teardown below.
    teardown: dict = {}
    vpc_id, subnet_ids = _create_vpc_with_subnets(ctx, teardown)
    name = f"{ctx.unique_name('sim2real-ds-caenroll').rstrip('-').lower()}.example.com"
    directory_id = ds.create_microsoft_ad(
        Name=name,
        Password=_PASSWORD,
        Edition="Standard",
        VpcSettings={"VpcId": vpc_id, "SubnetIds": subnet_ids},
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["DirectoryId"]
    ctx.on_cleanup(lambda: _delete_directory_and_wait(ds, directory_id, teardown))

    _wait_directory_active(ds, directory_id, timeout_s=2700.0)

    # Positive control: the read path and the fresh directory are healthy before we touch
    # CA enrollment at all.
    baseline = ds.describe_ca_enrollment_policy(DirectoryId=directory_id)
    assert baseline.get("CaEnrollmentPolicyStatus") not in ("Success", "InProgress"), (
        f"a freshly created directory must not already report an active CA enrollment "
        f"policy, got {baseline.get('CaEnrollmentPolicyStatus')!r}"
    )

    enable_error = _rejects(
        lambda: ds.enable_ca_enrollment_policy(DirectoryId=directory_id, PcaConnectorArn=fake_connector_arn)
    )
    assert enable_error["Code"] == "EntityDoesNotExistException", (
        f"expected EntityDoesNotExistException enabling with a nonexistent PCA connector, "
        f"got {enable_error['Code']}: {enable_error.get('Message')}"
    )
    # The message embeds the connector service's own error code and request id, which the check
    # never sees, so only the stable prefix and the suffix with this call's RequestId are exact.
    enable_message = enable_error.get("Message", "")
    assert enable_message.startswith(
        f"Connector not found for ARN: {fake_connector_arn}. Connector was not found: "
        f"{fake_connector_arn}. (Service: AWSPcaConnectorAd; Status Code: 404; Error Code: "
    ) and enable_message.endswith(f" : RequestId: {enable_error['RequestId']}"), (
        f"unexpected EntityDoesNotExistException message: {enable_message!r}"
    )

    after_enable = ds.describe_ca_enrollment_policy(DirectoryId=directory_id)
    assert after_enable.get("CaEnrollmentPolicyStatus") not in ("Success", "InProgress"), (
        f"a rejected Enable (nonexistent connector) must not leave the policy "
        f"InProgress/Success, got {after_enable.get('CaEnrollmentPolicyStatus')!r}"
    )
    assert after_enable.get("PcaConnectorArn") != fake_connector_arn, (
        "the rejected connector ARN must not be persisted onto the directory"
    )

    disable_error = _rejects(lambda: ds.disable_ca_enrollment_policy(DirectoryId=directory_id))
    assert disable_error["Code"] == "EntityDoesNotExistException", (
        f"expected EntityDoesNotExistException disabling a policy that was never "
        f"successfully enabled, got {disable_error['Code']}: {disable_error.get('Message')}"
    )
    assert disable_error.get("Message") == (
        f"No CA enrollment info found for directory {directory_id} with Inner Exception: "
        f"NoResultFoundException: No CA enrollment info found for directory {directory_id} "
        f": RequestId: {disable_error['RequestId']}"
    ), f"unexpected EntityDoesNotExistException message: {disable_error.get('Message')!r}"

    after_disable = ds.describe_ca_enrollment_policy(DirectoryId=directory_id)
    assert after_disable.get("CaEnrollmentPolicyStatus") not in ("Success", "InProgress"), (
        f"a rejected Disable must not change CaEnrollmentPolicyStatus, got "
        f"{after_disable.get('CaEnrollmentPolicyStatus')!r}"
    )

    # Positive control: the directory still accepts an unrelated mutation after the rejected calls.
    control_key = ctx.unique_name("sim2real-ds-caenroll-control-")
    ds.add_tags_to_resource(ResourceId=directory_id, Tags=[{"Key": control_key, "Value": "ok"}])
    tags_after = ds.list_tags_for_resource(ResourceId=directory_id)["Tags"]
    assert any(t["Key"] == control_key and t["Value"] == "ok" for t in tags_after), (
        "an unrelated tag mutation on the same directory should still succeed after the "
        "rejected CA-enrollment calls"
    )


def _rejects(fn):
    """Call fn() and return its botocore Error dict plus the call's RequestId; raises if fn()
    unexpectedly succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        return {**exc.response.get("Error", {}), "RequestId": exc.response["ResponseMetadata"]["RequestId"]}
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _create_vpc_with_subnets(ctx, teardown: dict, cidr_prefix: str = "10.95"):
    ec2 = ctx.client("ec2")
    vpc_id = ec2.create_vpc(
        CidrBlock=f"{cidr_prefix}.0.0/16",
        TagSpecifications=[
            {
                "ResourceType": "vpc",
                "Tags": [
                    {"Key": "Name", "Value": ctx.unique_name("sim2real-ds-vpc-")},
                    {"Key": "sim2real:managed", "Value": "true"},
                ],
            }
        ],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, teardown, "delete_vpc", VpcId=vpc_id))

    azs = [a["ZoneName"] for a in ec2.describe_availability_zones()["AvailabilityZones"]][:2]
    subnet_ids = []
    for i, az in enumerate(azs):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"{cidr_prefix}.{i}.0/24",
            AvailabilityZone=az,
            TagSpecifications=[
                {
                    "ResourceType": "subnet",
                    "Tags": [
                        {"Key": "Name", "Value": ctx.unique_name("sim2real-ds-subnet-")},
                        {"Key": "sim2real:managed", "Value": "true"},
                    ],
                }
            ],
        )["Subnet"]["SubnetId"]
        ctx.on_cleanup(lambda sid=subnet_id: _delete_net(ec2, teardown, "delete_subnet", SubnetId=sid))
        subnet_ids.append(subnet_id)
    return vpc_id, subnet_ids


def _wait_directory_active(ds, directory_id, timeout_s=2700.0, interval_s=30.0):
    deadline = time.monotonic() + timeout_s
    stage = None
    while time.monotonic() < deadline:
        desc = ds.describe_directories(DirectoryIds=[directory_id])["DirectoryDescriptions"][0]
        stage = desc["Stage"]
        if stage == "Active":
            return desc
        if stage == "Failed":
            raise AssertionError(f"directory {directory_id} entered Failed stage")
        time.sleep(interval_s)
    raise AssertionError(f"directory {directory_id} did not reach Active (last stage={stage})")


#: The suite's 1800 s cleanup budget, less a margin: every teardown of the run shares this one
#: deadline, started by the first teardown that asks for it.
_TEARDOWN_BUDGET_S = 1740.0
_NET_ENI_FILTER = {"VpcId": "vpc-id", "SubnetId": "subnet-id", "GroupId": "group-id"}
_NET_GONE = ("InvalidVpcID.NotFound", "InvalidSubnetID.NotFound")


def _teardown_deadline(teardown: dict) -> float:
    return teardown.setdefault("t", time.monotonic() + _TEARDOWN_BUDGET_S)


def _delete_directory_and_wait(ds, directory_id, teardown: dict) -> None:
    """Delete the directory and poll every 2 s until it is gone: EntityDoesNotExistException or
    Stage Deleted (a deleted directory keeps describing). A ClientException while the directory
    is still being created is retried; anything else, or the run's teardown deadline, raises."""
    deadline = _teardown_deadline(teardown)
    while True:
        try:
            ds.delete_directory(DirectoryId=directory_id)
            break
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code == "EntityDoesNotExistException":
                return
            stage = ds.describe_directories(DirectoryIds=[directory_id])["DirectoryDescriptions"][0]["Stage"]
            busy = code == "ClientException" and stage in ("Requested", "Creating", "Created")
            if not busy or time.monotonic() >= deadline:
                raise
        time.sleep(2)
    stage = None
    while True:
        try:
            found = ds.describe_directories(DirectoryIds=[directory_id])["DirectoryDescriptions"]
        except ClientError as err:
            if err.response["Error"]["Code"] == "EntityDoesNotExistException":
                return
            raise
        stage = found[0]["Stage"] if found else "Deleted"
        if stage == "Deleted":
            return
        if time.monotonic() >= deadline:
            raise RuntimeError(f"directory {directory_id} is still {stage} at the teardown deadline")
        time.sleep(2)


def _delete_net(client, teardown: dict, op, **ident):
    """Run an EC2 network delete: a not-found answer is done; DependencyViolation (the directory's
    ENIs leave the subnets after it is deleted) is retried every 2 s to the run's teardown deadline,
    then raised naming the ENIs still attached."""
    deadline = _teardown_deadline(teardown)
    flt = [{"Name": _NET_ENI_FILTER[k], "Values": [v]} for k, v in ident.items() if k in _NET_ENI_FILTER]
    while True:
        try:
            return getattr(client, op)(**ident)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code in _NET_GONE:
                return None
            if code != "DependencyViolation":
                raise
            if time.monotonic() >= deadline:
                # Same exception type and code, so a caller catching ClientError still collects it.
                raise type(exc)(
                    {**exc.response, "Error": {**exc.response.get("Error", {}), "Message": (
                        f"{op}({ident}): DependencyViolation at the teardown deadline; "
                        f"ENIs still attached: {_net_enis(client, flt)}"
                    )}},
                    exc.operation_name,
                ) from exc
        time.sleep(2)


def _net_enis(client, flt):
    from botocore.exceptions import ClientError as _ClientError

    if not flt:
        return []
    try:
        enis = client.describe_network_interfaces(Filters=flt)["NetworkInterfaces"]
    except _ClientError:
        return []  # a diagnostic only: the delete itself still reports its own failure
    return [f"{e['NetworkInterfaceId']}:{e.get('InterfaceType') or e.get('Description', '')[:40]}" for e in enis]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
