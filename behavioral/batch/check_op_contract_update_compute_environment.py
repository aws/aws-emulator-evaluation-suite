"""op-contract-update-compute-environment."""
from __future__ import annotations

import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-update-compute-environment"
GROUP = "error-semantics"
SERVICES = ["batch"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateComputeEnvironment applies a maxvCpus change to a FARGATE CE, which settles VALID.

    Setting the EC2-only instanceRole is refused with ClientException and leaves the CE unchanged.
    """

    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available to place a FARGATE compute environment")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    if not subnets:
        raise AssertionError("shared network has no subnets")
    subnet_id = subnets[0]["SubnetId"]
    sgs = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"]
    if not sgs:
        raise AssertionError("shared network has no default security group")
    sg_id = sgs[0]["GroupId"]

    batch = ctx.client("batch")
    name = ctx.unique_name("sim2real-batch-ce-")
    created = batch.create_compute_environment(
        computeEnvironmentName=name,
        type="MANAGED",
        state="ENABLED",
        computeResources={
            "type": "FARGATE",
            "maxvCpus": 4,
            "subnets": [subnet_id],
            "securityGroupIds": [sg_id],
        },
        tags={"sim2real": "true"},
    )
    ce_arn = created["computeEnvironmentArn"]
    ctx.on_cleanup(lambda: _delete_ce(ctx, name))

    ce = _wait_ce_status(ctx, name, timeout_s=240)
    assert ce["status"] == "VALID", ce.get("statusReason")
    assert ce["computeResources"]["maxvCpus"] == 4, ce["computeResources"]

    resp = batch.update_compute_environment(computeEnvironment=name, computeResources={"maxvCpus": 8})
    assert resp["computeEnvironmentArn"] == ce_arn, (resp["computeEnvironmentArn"], ce_arn)
    assert resp["computeEnvironmentName"] == name, resp["computeEnvironmentName"]

    ce2 = _wait_ce_status(ctx, name, timeout_s=240)
    assert ce2["status"] == "VALID", ce2.get("statusReason")
    assert ce2["computeResources"]["maxvCpus"] == 8, ce2["computeResources"]

    # error boundary: instanceRole is an EC2/SPOT-only field, unsupported for FARGATE CEs
    code, message = _client_error(
        lambda: batch.update_compute_environment(
            computeEnvironment=name,
            computeResources={"instanceRole": f"arn:aws:iam::{_dummy_account(ctx)}:instance-profile/bogus"},
        )
    )
    assert code == "ClientException", code
    expected = (
        "The following parameters can\\'t be updated for Fargate compute environment: allocationStrategy, "
        "bidPercentage, ec2Configuration, ec2KeyPair, imageId, instanceRole, instanceTypes, launchTemplate, "
        "placementGroup, tags, type, updatePolicy, updateToLatestImageVersion."
    )
    assert message == expected, f"expected {expected!r}, got {message!r}"

    ce3 = batch.describe_compute_environments(computeEnvironments=[name])["computeEnvironments"][0]
    assert ce3["computeResources"]["maxvCpus"] == 8, ce3["computeResources"]
    assert ce3["computeResources"]["type"] == "FARGATE", ce3["computeResources"]["type"]
    assert "instanceRole" not in ce3["computeResources"], ce3["computeResources"]


def _client_error(fn) -> tuple[str, str | None]:
    """Call fn(); return (Error.Code, Error.Message) of the ClientError it raises. An unexpected
    SUCCESS raises, so accepting what AWS refuses fails loudly."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _dummy_account(ctx) -> str:
    return ctx.client("sts").get_caller_identity()["Account"]


def _wait_ce_status(ctx, name: str, timeout_s: float = 240.0) -> dict[str, Any]:
    batch = ctx.client("batch")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        ces = batch.describe_compute_environments(computeEnvironments=[name])["computeEnvironments"]
        if ces and ces[0]["status"] in ("VALID", "INVALID"):
            return ces[0]
        time.sleep(3)
    raise AssertionError(f"compute environment {name} did not reach a terminal status within {timeout_s}s")


def _delete_ce(ctx, name: str) -> None:
    batch = ctx.client("batch")
    try:
        batch.update_compute_environment(computeEnvironment=name, state="DISABLED")
        _wait_ce_status(ctx, name, timeout_s=240)
    except ClientError as exc:
        err = exc.response["Error"]
        if not (err["Code"] == "ClientException" and "does not exist" in err.get("Message", "")):
            raise
    _delete_compute_environment_and_wait(batch, name)



def _delete_compute_environment_and_wait(batch, name, timeout_s=300.0, interval_s=5.0):
    """DeleteComputeEnvironment, then wait until it is gone. The delete is asynchronous and needs
    the service role until it completes, so returning early lets a later cleanup delete the role
    and strand the environment."""
    from botocore.exceptions import ClientError

    retry_deadline = time.monotonic() + timeout_s
    while True:
        if not [ce for ce in batch.describe_compute_environments(computeEnvironments=[name])["computeEnvironments"]
                if ce.get("status") != "DELETED"]:
            return
        try:
            batch.delete_compute_environment(computeEnvironment=name)
            break
        except ClientError as e:  # still UPDATING, or a job queue being deleted still references it
            if e.response["Error"]["Code"] != "ClientException" or time.monotonic() >= retry_deadline:
                raise
            time.sleep(interval_s)
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        found = batch.describe_compute_environments(computeEnvironments=[name])["computeEnvironments"]
        if not [ce for ce in found if ce.get("status") != "DELETED"]:
            return
        time.sleep(interval_s)
    raise AssertionError(f"compute environment {name} still present {timeout_s:.0f}s after delete")

if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
