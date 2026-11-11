"""op-contract-request-spot-fleet."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-request-spot-fleet"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """RequestSpotFleet accepts a valid fleet config and creates a trackable
    fleet request (success contract), and rejects a config referencing an
    IAM fleet role that does not exist."""
    ec2 = ctx.client("ec2")
    iam = ctx.client("iam")

    role_arn, role_created = _ensure_spot_fleet_role(iam, ctx)
    ami_id = _latest_al2023_ami(ec2)

    fleet_name = ctx.unique_name("sim2real-rsf-fleet-")
    config = {
        "IamFleetRole": role_arn,
        "AllocationStrategy": "lowestPrice",
        "TargetCapacity": 1,
        "Type": "request",
        "LaunchSpecifications": [{"ImageId": ami_id, "InstanceType": "t3.micro"}],
        "TagSpecifications": [
            {"ResourceType": "spot-fleet-request", "Tags": [{"Key": "Name", "Value": fleet_name}]}
        ],
    }
    # A freshly-created IAM role can take a little while to propagate before
    # the Spot Fleet service will accept it as a valid IamFleetRole.
    fleet_id = _poll_until_success(
        lambda: ec2.request_spot_fleet(SpotFleetRequestConfig=config)["SpotFleetRequestId"],
        retryable_codes={"InvalidSpotFleetRequestConfig"} if role_created else set(),
        timeout_s=90, interval_s=5)
    ctx.on_cleanup(lambda: _cancel_fleet_and_reap_instances(ec2, fleet_id))

    state = _poll_until(
        lambda: ec2.describe_spot_fleet_requests(SpotFleetRequestIds=[fleet_id])
        ["SpotFleetRequestConfigs"][0]["SpotFleetRequestState"],
        lambda s: s in ("submitted", "active", "failed", "modifying"), timeout_s=90, interval_s=5)
    assert state != "failed", (
        f"spot fleet request {fleet_id} entered state 'failed', expected one of "
        "submitted/active/modifying")

    bogus_role = f"arn:aws:iam::111122223333:role/sim2real-nonexistent-{ctx.unique_name('x')}"
    bad_config = dict(config, IamFleetRole=bogus_role)
    code, message = _error(lambda: ec2.request_spot_fleet(SpotFleetRequestConfig=bad_config))
    assert code == "InvalidSpotFleetRequestConfig", f"expected InvalidSpotFleetRequestConfig, got {code}"
    assert message == "Parameter: SpotFleetRequestConfig.IamFleetRole is invalid.", (
        f"unexpected InvalidSpotFleetRequestConfig message {message!r}")

    # Effect-absent, at the destination: the rejected call must not have created a fleet
    # request anyway. bogus_role is unique to this run, so scanning every fleet request in
    # the (shared) account for one referencing it is unambiguous under concurrency.
    leaked = list(_spot_fleet_ids_with_role(ec2, bogus_role))
    assert leaked == [], (
        f"RequestSpotFleet returned {code!r} but created fleet request(s) anyway: {leaked}")


def _error(fn):
    """Call fn() and return the (code, message) of the ClientError it raises; a call that
    succeeds raises AssertionError."""
    from botocore.exceptions import ClientError
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded with {result!r}")


def _poll_until(probe, predicate, timeout_s=120.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _cancel_fleet_and_reap_instances(ec2, fleet_id: str) -> None:
    """CancelSpotFleetRequests(TerminateInstances=True) can race a fleet still fulfilling
    its target capacity: an instance whose launch was already dispatched by the Spot Fleet
    backend at cancellation time can come up running anyway, untracked by that one call. Poll
    for stragglers and terminate them directly rather than trusting the single best-effort
    call."""
    ec2.cancel_spot_fleet_requests(SpotFleetRequestIds=[fleet_id], TerminateInstances=True)
    deadline = time.monotonic() + 40.0
    stragglers: list[str] = []
    while time.monotonic() < deadline:
        stragglers = [
            i["InstanceId"]
            for i in ec2.describe_spot_fleet_instances(SpotFleetRequestId=fleet_id)["ActiveInstances"]
        ]
        if not stragglers:
            return
        time.sleep(5)
    ec2.terminate_instances(InstanceIds=stragglers)


def _spot_fleet_ids_with_role(ec2, role_arn: str):
    token = None
    while True:
        kwargs = {"NextToken": token} if token else {}
        resp = ec2.describe_spot_fleet_requests(**kwargs)
        for cfg in resp["SpotFleetRequestConfigs"]:
            if cfg["SpotFleetRequestConfig"].get("IamFleetRole") == role_arn:
                yield cfg["SpotFleetRequestId"]
        token = resp.get("NextToken")
        if not token:
            return


def _latest_al2023_ami(ec2) -> str:
    images = ec2.describe_images(
        Owners=["amazon"],
        Filters=[
            {"Name": "name", "Values": ["al2023-ami-*-x86_64"]},
            {"Name": "state", "Values": ["available"]},
        ],
    )["Images"]
    if not images:
        raise AssertionError("no al2023 AMI found in this region")
    images.sort(key=lambda i: i["CreationDate"], reverse=True)
    return images[0]["ImageId"]


def _poll_until_success(fn, retryable_codes, timeout_s=120.0, interval_s=5.0):
    from botocore.exceptions import ClientError
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in retryable_codes:
                raise
            last_exc = exc
            time.sleep(interval_s)
    raise last_exc


def _ensure_spot_fleet_role(iam, ctx) -> tuple[str, bool]:
    """Return (role_arn, created) for a role Spot Fleet can assume.

    The EC2-managed service-linked role (AWSServiceRoleForEC2SpotFleet) is
    NOT accepted as an IamFleetRole value by RequestSpotFleet (AWS rejects it
    with InvalidSpotFleetRequestConfig); a regular IAM role trusting
    spotfleet.amazonaws.com with the AmazonEC2SpotFleetTaggingRole managed
    policy attached is required instead.
    """
    import json
    from botocore.exceptions import ClientError

    role_name = ctx.unique_name("sim2real-rsf-role-")
    trust_policy = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "spotfleet.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    })
    role = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=trust_policy,
        Tags=[{"Key": "Name", "Value": role_name}])["Role"]
    role_arn = role["Arn"]

    def _cleanup():
        try:
            iam.detach_role_policy(
                RoleName=role_name,
                PolicyArn="arn:aws:iam::aws:policy/service-role/AmazonEC2SpotFleetTaggingRole")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        iam.delete_role(RoleName=role_name)
    ctx.on_cleanup(_cleanup)

    iam.attach_role_policy(
        RoleName=role_name,
        PolicyArn="arn:aws:iam::aws:policy/service-role/AmazonEC2SpotFleetTaggingRole")
    return role_arn, True


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
