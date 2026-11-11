"""server-side-ca-enrollment-policy-toggle-enforced."""
from __future__ import annotations

import itertools
import time
import uuid

from behavioral_harness import tags
from botocore.exceptions import ClientError

# Zone IDs where AWS Directory Service cannot place a directory. Zone names map to different
# zones in each account, so the zones are named by ID.
_DS_UNSUPPORTED_ZONE_IDS = {"usw2-az4", "use1-az3", "use1-az5", "cac1-az4"}

CHECK = "server-side-ca-enrollment-policy-toggle-enforced"
GROUP = "server-side"
SERVICES = ["ds"]

_PASSWORD = "Sim2Real!Test2024"


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """EnableCAEnrollmentPolicy with a nonexistent PcaConnectorArn fails synchronously with
    EntityDoesNotExistException and leaves no active policy; DisableCAEnrollmentPolicy with no
    policy fails the same way, while DescribeCAEnrollmentPolicy keeps working throughout."""
    ds = ctx.client("ds")
    directory_id, _ = _create_microsoft_ad(ctx)

    account_id = ctx.client("sts").get_caller_identity()["Account"]
    fake_connector_arn = (
        f"arn:aws:pca-connector-ad:{ctx.region}:{account_id}:connector/{uuid.uuid4()}"
    )

    # Baseline: before any Enable attempt, Describe succeeds and reports no active policy.
    baseline = ds.describe_ca_enrollment_policy(DirectoryId=directory_id)
    assert baseline.get("CaEnrollmentPolicyStatus") not in ("Success", "InProgress"), (
        f"a freshly created directory must not already report an active CA enrollment "
        f"policy, got: {baseline.get('CaEnrollmentPolicyStatus')!r}"
    )

    err = _client_error(
        lambda: ds.enable_ca_enrollment_policy(
            DirectoryId=directory_id, PcaConnectorArn=fake_connector_arn
        )
    )
    # The message embeds the request id of DS's inner PCA Connector AD call, which the response
    # does not expose, so its stable prefix and suffix are asserted.
    _assert_code(err, "EntityDoesNotExistException")
    enable_prefix = (
        f"Connector not found for ARN: {fake_connector_arn}. Connector was not found: "
        f"{fake_connector_arn}. (Service: AWSPcaConnectorAd; Status Code: 404; Error Code: "
        "ResourceNotFoundException; Request ID: "
    )
    enable_message = err.get("Error", {}).get("Message") or ""
    enable_suffix = f"; Proxy: null) : RequestId: {_request_id(err)}"
    assert enable_message.startswith(enable_prefix) and enable_message.endswith(enable_suffix), (
        f"expected a message starting {enable_prefix!r} and ending {enable_suffix!r}, got {enable_message!r}"
    )

    after_failed_enable = ds.describe_ca_enrollment_policy(DirectoryId=directory_id)
    assert after_failed_enable.get("CaEnrollmentPolicyStatus") not in ("Success", "InProgress"), (
        "a rejected Enable (nonexistent connector) must not leave the policy InProgress/Success: "
        f"got {after_failed_enable.get('CaEnrollmentPolicyStatus')!r}"
    )
    assert after_failed_enable.get("PcaConnectorArn") != fake_connector_arn, (
        "the rejected connector ARN must not be persisted onto the directory"
    )

    disable_err = _client_error(lambda: ds.disable_ca_enrollment_policy(DirectoryId=directory_id))
    _assert_code(disable_err, "EntityDoesNotExistException")
    disable_expected = (
        f"No CA enrollment info found for directory {directory_id} with Inner Exception: "
        f"NoResultFoundException: No CA enrollment info found for directory {directory_id} : "
        f"RequestId: {_request_id(disable_err)}"
    )
    disable_message = disable_err.get("Error", {}).get("Message")
    assert disable_message == disable_expected, f"expected {disable_expected!r}, got {disable_message!r}"

    # Re-attempting Enable with the same bad connector must fail the same way, not get stuck
    # "in progress" from the first rejected attempt.
    retry_err = _client_error(
        lambda: ds.enable_ca_enrollment_policy(
            DirectoryId=directory_id, PcaConnectorArn=fake_connector_arn
        )
    )
    # The message again embeds the inner PCA Connector AD request id.
    _assert_code(retry_err, "EntityDoesNotExistException")
    retry_message = retry_err.get("Error", {}).get("Message") or ""
    retry_suffix = f"; Proxy: null) : RequestId: {_request_id(retry_err)}"
    assert retry_message.startswith(enable_prefix) and retry_message.endswith(retry_suffix), (
        f"expected a message starting {enable_prefix!r} and ending {retry_suffix!r}, got {retry_message!r}"
    )

    # Positive control: the read path still returns a well-formed response after the rejections.
    final = ds.describe_ca_enrollment_policy(DirectoryId=directory_id)
    assert final.get("CaEnrollmentPolicyStatus") not in ("Success", "InProgress"), (
        "the read path must still report no active policy after the rejected attempts, got: "
        f"{final.get('CaEnrollmentPolicyStatus')!r}"
    )
    assert final.get("PcaConnectorArn") != fake_connector_arn, (
        "the read path must not echo the rejected connector ARN even after the repeated "
        f"rejected attempts, got: {final.get('PcaConnectorArn')!r}"
    )


def _client_error(fn):
    """Call fn() and return the refusal's response; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response
    raise AssertionError(f"real AWS refuses this call, but it succeeded and returned {result!r}")


def _request_id(err) -> str:
    return err.get("ResponseMetadata", {}).get("RequestId", "")


def _assert_code(err, code) -> None:
    got_code = err.get("Error", {}).get("Code")
    assert got_code == code, f"expected {code}, got {got_code!r}"


def _pick_vpc_and_subnets(ctx):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}]).get("Vpcs", [])
    if not vpcs:
        raise AssertionError(f"the run's shared network {ctx.network().vpc_id} is not visible")
    for vpc in vpcs:
        subnets = ec2.describe_subnets(
            Filters=[{"Name": "vpc-id", "Values": [vpc["VpcId"]]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}]
        ).get("Subnets", [])
        subnets = sorted((s for s in subnets if s.get("AvailabilityZoneId") not in _DS_UNSUPPORTED_ZONE_IDS), key=lambda s: s["AvailabilityZone"])
        by_az: dict[str, str] = {}
        for sn in subnets:
            by_az.setdefault(sn["AvailabilityZone"], sn["SubnetId"])
        if len(by_az) >= 2:
            # Return every candidate subnet, not just two: CreateMicrosoftAD rejects
            # specific AZs as capacity-constrained ("Failed to locate Availability Zone"),
            # and which AZ is unsupported varies by account/region, so the caller must be
            # able to retry with a different pair rather than being handed a fixed two.
            return vpc["VpcId"], list(by_az.values())
    raise AssertionError("no VPC with subnets in >=2 availability zones to provision a DS directory")


def _wait_directory_stage(ctx, directory_id, target_stages, timeout_s=3600, interval_s=30):
    ds = ctx.client("ds")
    deadline = time.monotonic() + timeout_s
    stage = None
    while time.monotonic() < deadline:
        desc = ds.describe_directories(DirectoryIds=[directory_id])["DirectoryDescriptions"][0]
        stage = desc["Stage"]
        if stage in target_stages:
            return desc
        if stage in ("Failed", "Inoperable"):
            raise AssertionError(f"directory entered terminal failure stage {stage}")
        time.sleep(interval_s)
    raise AssertionError(f"directory did not reach {target_stages} within {timeout_s}s (last={stage})")


def _create_microsoft_ad(ctx, name_prefix="sim2realmsad"):
    ds = ctx.client("ds")
    vpc_id, subnet_ids = _pick_vpc_and_subnets(ctx)
    name = f"{ctx.unique_name(name_prefix)}.test"

    last_error = None
    directory_id = None
    for pair in itertools.combinations(subnet_ids, 2):
        try:
            directory_id = ds.create_microsoft_ad(
                Name=name,
                Password=_PASSWORD,
                VpcSettings={"VpcId": vpc_id, "SubnetIds": list(pair)},
                Edition="Standard",
                Tags=[
                    {"Key": "sim2real", "Value": "behavioral"},
                    {"Key": "sim2real-check", "Value": CHECK},
                ],
            )["DirectoryId"]
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ClientException" and (
                "Failed to locate Availability Zone" in str(exc)
            ):
                last_error = exc
                continue
            raise
    if directory_id is None:
        raise AssertionError(
            f"no subnet pair supports CreateMicrosoftAD in this account/region: {last_error}"
        )

    def _cleanup():
        try:
            ds.delete_directory(DirectoryId=directory_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in (
                "DirectoryDoesNotExistException",
                "EntityDoesNotExistException",
            ):
                raise

    ctx.on_cleanup(_cleanup)
    _wait_directory_stage(ctx, directory_id, {"Active"})
    return directory_id, name


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
