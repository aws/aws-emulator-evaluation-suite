"""ssm-patch-baseline-scan-reports-compliance-for-a-real-instance."""
from __future__ import annotations

import collections
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "ssm-patch-baseline-scan-reports-compliance-for-a-real-instance"
GROUP = 'patch-manager'
SERVICES = ['ec2', 'ssm']

_AL2023_AMI_PARAM = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
_SSM_CORE_POLICY = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
_INSTANCE_TYPE = "t3.micro"
_OS = "AMAZON_LINUX_2023"
_TERMINAL = ("Success", "Cancelled", "TimedOut", "Failed", "Cancelling")
_THROTTLE = ("Throttling", "ThrottlingException", "RequestLimitExceeded", "TooManyUpdates")


def _call_with_retry(fn, codes=_THROTTLE, retries=30, delay=2.0):
    last = None
    for _ in range(retries):
        try:
            return fn()
        except ClientError as exc:
            last = exc
            if exc.response.get("Error", {}).get("Code") in codes:
                time.sleep(delay)
                continue
            raise
    raise last


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll(probe, predicate, timeout_s, interval_s=1.0, what="", *, ctx):
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"{what or 'condition'}: the run budget ended first; not graded")
            raise AssertionError(
                f"{what or 'condition'} not met within {timeout_s:.0f}s (last observed: {last!r})"
            )
        time.sleep(min(interval_s, max(0.0, deadline - time.monotonic())))


def _usable_subnet(ec2, *, ctx):
    """A default-VPC public subnet in an AZ that both is available and offers the type."""
    offered = {
        o["Location"]
        for o in ec2.describe_instance_type_offerings(
            LocationType="availability-zone",
            Filters=[{"Name": "instance-type", "Values": [_INSTANCE_TYPE]}, {"Name": "location", "Values": ctx.network().availability_zones}],
        )["InstanceTypeOfferings"]
    }
    available = {
        z["ZoneName"]
        for z in ec2.describe_availability_zones(
            Filters=[{"Name": "state", "Values": ["available"]}, {"Name": "zone-name", "Values": ctx.network().availability_zones}]
        )["AvailabilityZones"]
    }
    usable = sorted(offered & available)
    assert usable, (
        f"no available AZ in this region offers {_INSTANCE_TYPE}; offered {sorted(offered)!r}, "
        f"available {sorted(available)!r}"
    )
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    assert len(vpcs) == 1, f"expected exactly one shared network, got {vpcs!r}"
    subnets = ec2.describe_subnets(
        Filters=[{"Name": "vpc-id", "Values": [vpcs[0]["VpcId"]]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}]
    )["Subnets"]
    candidates = [
        s
        for s in subnets
        if s["AvailabilityZone"] in usable and s.get("MapPublicIpOnLaunch")
    ]
    assert candidates, (
        "the agent must reach the SSM endpoint to register and the scan must reach the "
        f"package repositories, so the instance needs a public subnet in one of {usable!r}"
    )
    return candidates[0]["SubnetId"], candidates[0]["AvailabilityZone"]


def _terminate_and_wait(ec2, instance_id, timeout_s=180):
    try:
        _call_with_retry(lambda: ec2.terminate_instances(InstanceIds=[instance_id]))
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "InvalidInstanceID.NotFound":
            raise
        return
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        states = [
            i["State"]["Name"]
            for r in ec2.describe_instances(InstanceIds=[instance_id])["Reservations"]
            for i in r["Instances"]
        ]
        if all(s in ("shutting-down", "terminated") for s in states):
            return
        time.sleep(2)


def _drop_instance_profile(iam, profile_name, role_name):
    for attempt in range(30):
        try:
            iam.remove_role_from_instance_profile(
                InstanceProfileName=profile_name, RoleName=role_name
            )
            break
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "NoSuchEntity":
                break
            if attempt == 29:
                raise
            time.sleep(2)
    for attempt in range(30):
        try:
            iam.delete_instance_profile(InstanceProfileName=profile_name)
            return
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "NoSuchEntity":
                return
            if attempt == 29:
                raise
            time.sleep(2)


def _drop_role(iam, role_name):
    try:
        iam.detach_role_policy(RoleName=role_name, PolicyArn=_SSM_CORE_POLICY)
    except ClientError as err:
        if err.response["Error"]["Code"] != "NoSuchEntity":
            raise
    for attempt in range(30):
        try:
            iam.delete_role(RoleName=role_name)
            return
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "NoSuchEntity":
                return
            if attempt == 29:
                raise
            time.sleep(2)


def _drop_baseline(ssm, baseline_id, patch_group):
    """Deregister the group first: DeletePatchBaseline is refused while a group references it."""
    for attempt in range(30):
        try:
            ssm.deregister_patch_baseline_for_patch_group(
                BaselineId=baseline_id, PatchGroup=patch_group
            )
            break
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") in (
                "DoesNotExistException",
                "InvalidResourceId",
            ):
                break
            if attempt == 29:
                raise
            time.sleep(2)
    for attempt in range(30):
        try:
            ssm.delete_patch_baseline(BaselineId=baseline_id)
            return
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "DoesNotExistException":
                return
            if attempt == 29:
                raise
            time.sleep(2)


@tags(
    "axis:happy-path",
    "concern:data-plane",
    "concern:e2e",
    "dp:api",
    "plane:data",
    "cap:c1",
    "cap:c5",
)
def run(ctx) -> None:
    """An AWS-RunPatchBaseline Scan on a real instance reports this check's own baseline, and each
    per-state summary count matches the DescribeInstancePatches record tally.

    Reference: https://docs.aws.amazon.com/systems-manager/latest/userguide/patch-manager-aws-runpatchbaseline.html
    """

    ssm = ctx.client("ssm")
    ec2 = ctx.client("ec2")
    iam = ctx.client("iam")

    # --- a baseline of this check's own, and a patch group only it uses -------
    patch_group = ctx.unique_name("sim2real-behav-pg-")
    baseline = ssm.create_patch_baseline(
        Name=ctx.unique_name("sim2real-behav-pb-")[:128],
        OperatingSystem=_OS,
        Description="sim2real-behav patch scan baseline",
        ApprovalRules={
            "PatchRules": [
                {
                    "PatchFilterGroup": {
                        "PatchFilters": [
                            {"Key": "CLASSIFICATION", "Values": ["Security", "Bugfix", "Enhancement", "Recommended", "Newpackage"]},
                            {
                                "Key": "SEVERITY",
                                "Values": ["Critical", "Important", "Medium", "Low"],
                            },
                        ]
                    },
                    "ApproveAfterDays": 0,
                    "ComplianceLevel": "CRITICAL",
                    "EnableNonSecurity": True,
                }
            ]
        },
        Tags=[{"Key": "sim2real", "Value": "patch-baseline-scan"}],
    )
    baseline_id = baseline["BaselineId"]
    ctx.on_cleanup(lambda: _drop_baseline(ssm, baseline_id, patch_group))
    ssm.register_patch_baseline_for_patch_group(
        BaselineId=baseline_id, PatchGroup=patch_group
    )

    resolved = ssm.get_patch_baseline_for_patch_group(
        PatchGroup=patch_group, OperatingSystem=_OS
    )
    assert resolved["BaselineId"].endswith(baseline_id.rsplit("/", 1)[-1]), (
        "the patch group must resolve to the baseline just registered to it; got "
        f"{resolved['BaselineId']!r}, registered {baseline_id!r}"
    )

    # --- the managed instance, tagged into that patch group ------------------
    role_name = ctx.unique_name("sim2real-behav-patch-")
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": "ec2.amazonaws.com"},
                        "Action": "sts:AssumeRole",
                    }
                ],
            }
        ),
        Description="sim2real-behav patch scan managed instance role",
        Tags=[{"Key": "sim2real", "Value": "patch-baseline-scan"}],
    )
    ctx.on_cleanup(lambda: _drop_role(iam, role_name))
    iam.attach_role_policy(RoleName=role_name, PolicyArn=_SSM_CORE_POLICY)

    profile_name = role_name
    iam.create_instance_profile(
        InstanceProfileName=profile_name,
        Tags=[{"Key": "sim2real", "Value": "patch-baseline-scan"}],
    )
    ctx.on_cleanup(lambda: _drop_instance_profile(iam, profile_name, role_name))
    iam.add_role_to_instance_profile(
        InstanceProfileName=profile_name, RoleName=role_name
    )

    ami = ssm.get_parameter(Name=_AL2023_AMI_PARAM)["Parameter"]["Value"]
    subnet_id, zone = _usable_subnet(ec2, ctx=ctx)
    # "Patch Group" — with the space — is the tag key Patch Manager reads.
    tag_spec = [
        {
            "ResourceType": "instance",
            "Tags": [
                {"Key": "Name", "Value": role_name},
                {"Key": "Patch Group", "Value": patch_group},
                {"Key": "sim2real", "Value": "patch-baseline-scan"},
            ],
        },
        {
            "ResourceType": "volume",
            "Tags": [{"Key": "sim2real", "Value": "patch-baseline-scan"}],
        },
    ]
    reservation = _call_with_retry(
        lambda: ec2.run_instances(
            ImageId=ami,
            InstanceType=_INSTANCE_TYPE,
            MinCount=1,
            MaxCount=1,
            SubnetId=subnet_id,
            IamInstanceProfile={"Name": profile_name},
            TagSpecifications=tag_spec,
        ),
        codes=_THROTTLE + ("InvalidParameterValue",),
        retries=60,
        delay=2.0,
    )
    instance_id = reservation["Instances"][0]["InstanceId"]
    ctx.on_cleanup(lambda: _terminate_and_wait(ec2, instance_id))
    assert reservation["Instances"][0]["Placement"]["AvailabilityZone"] == zone, (
        f"the instance landed in {reservation['Instances'][0]['Placement']!r}, not {zone!r}"
    )

    def _agent_view():
        for page in ssm.get_paginator("describe_instance_information").paginate():
            for info in page["InstanceInformationList"]:
                if info.get("InstanceId") == instance_id:
                    return info
        return None

    info = _poll(
        _agent_view,
        lambda i: i is not None and i.get("PingStatus") == "Online",
        timeout_s=300,
        interval_s=1.0,
        what=f"the SSM agent on {instance_id} coming Online", ctx=ctx,
    )
    assert info["PingStatus"] == "Online", f"instance {instance_id!r} is {info!r}"

    # --- the scan (not Install: installing can reboot and is not deterministic) ---
    sent = _call_with_retry(
        lambda: ssm.send_command(
            InstanceIds=[instance_id],
            DocumentName="AWS-RunPatchBaseline",
            Parameters={"Operation": ["Scan"], "RebootOption": ["NoReboot"]},
            TimeoutSeconds=600,
            Comment="sim2real-behav patch scan",
        )
    )
    command_id = sent["Command"]["CommandId"]

    def _invocation():
        try:
            return ssm.get_command_invocation(
                CommandId=command_id, InstanceId=instance_id
            )
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "InvocationDoesNotExist":
                return None
            raise

    inv = _poll(
        _invocation,
        lambda i: i is not None and i.get("Status") in _TERMINAL,
        timeout_s=900,
        interval_s=1.0,
        what=f"the patch scan invocation {command_id} reaching a terminal status", ctx=ctx,
    )
    assert inv["Status"] == "Success", (
        f"the patch scan invocation was {inv['Status']!r}: {inv.get('StatusDetails')!r} "
        f"stderr={inv.get('StandardErrorContent')[-600:]!r}"
    )
    assert inv["ResponseCode"] == 0, f"ResponseCode was {inv['ResponseCode']!r}"

    # --- the compliance summary the scan produced ---------------------------
    def _states():
        return ssm.describe_instance_patch_states(InstanceIds=[instance_id])[
            "InstancePatchStates"
        ]

    states = _poll(
        _states,
        lambda s: len(s) == 1 and s[0].get("Operation"),
        timeout_s=600,
        interval_s=1.0,
        what=f"a patch state appearing for {instance_id}", ctx=ctx,
    )
    state = states[0]
    assert state["InstanceId"] == instance_id, (
        f"the patch state must be attributed to {instance_id!r}, got {state!r}"
    )
    assert state["BaselineId"].endswith(baseline_id.rsplit("/", 1)[-1]), (
        "the scan must have used the baseline registered to this instance's patch group, "
        f"not the AWS default; got {state['BaselineId']!r}, expected {baseline_id!r}"
    )
    assert state["PatchGroup"] == patch_group, (
        f"the state must report the patch group the instance was tagged into; got "
        f"{state.get('PatchGroup')!r}, expected {patch_group!r}"
    )
    assert state["Operation"] == "Scan", f"Operation was {state['Operation']!r}"
    assert state["OperationEndTime"] >= state["OperationStartTime"], (
        f"the scan ended at {state['OperationEndTime']} before it started at "
        f"{state['OperationStartTime']}"
    )

    # --- the individual records the summary was computed from ----------------
    # DescribeInstancePatches lands after DescribeInstancePatchStates, so poll it;
    # an empty result at the deadline is a FAIL, never a skip.
    def _list_patches():
        out = []
        for page in ssm.get_paginator("describe_instance_patches").paginate(
            InstanceId=instance_id
        ):
            out += page["Patches"]
        return out

    _counter_keys = (
        "InstalledCount",
        "InstalledOtherCount",
        "InstalledPendingRebootCount",
        "InstalledRejectedCount",
        "MissingCount",
        "FailedCount",
        "NotApplicableCount",
        "UnreportedNotApplicableCount",
    )
    patches = _poll(
        _list_patches,
        lambda ps: len(ps) > 0,
        timeout_s=600,
        interval_s=2.0,
        what=(
            "DescribeInstancePatches returning at least one record for the scan (summary "
            f"counters were {{k: state.get(k) for k in _counter_keys}} = "
            f"{ {k: state.get(k) for k in _counter_keys} !r})"
        ), ctx=ctx,
    )
    # Re-read the summary now that the record set has landed: both halves of the
    # cross-check must come from the settled scan.
    settled = ssm.describe_instance_patch_states(InstanceIds=[instance_id])[
        "InstancePatchStates"
    ]
    assert len(settled) == 1, f"expected one patch state, got {settled!r}"
    state = settled[0]
    for p in patches:
        assert p.get("Title"), f"a patch record carries no Title: {p!r}"
        assert p.get("KBId"), f"a patch record carries no KBId: {p!r}"

    by_state = collections.Counter(p["State"] for p in patches)
    # Every counter over a state SSM reports BY NAME must be exactly recomputable
    # from the record set. NotApplicableCount can exceed the NotApplicable records even
    # after subtracting UnreportedNotApplicableCount, so it is only bounded from below.
    exact = {
        "Installed": state["InstalledCount"],
        "InstalledOther": state["InstalledOtherCount"],
        "InstalledPendingReboot": state.get("InstalledPendingRebootCount", 0),
        "InstalledRejected": state.get("InstalledRejectedCount", 0),
        "Missing": state["MissingCount"],
        "Failed": state["FailedCount"],
    }
    for patch_state, summary_count in exact.items():
        assert by_state.get(patch_state, 0) == summary_count, (
            f"the summary reports {summary_count} patches in state {patch_state!r} but "
            f"DescribeInstancePatches returned {by_state.get(patch_state, 0)}; full record "
            f"tally {dict(by_state)!r} against summary {exact!r}"
        )
    assert sum(exact.values()) + by_state.get("NotApplicable", 0) == len(patches), (
        f"the per-state counters plus the NotApplicable records sum to "
        f"{sum(exact.values()) + by_state.get('NotApplicable', 0)} but {len(patches)} records "
        f"were returned, so the record set holds a state no counter covers; tally "
        f"{dict(by_state)!r}"
    )
    assert state["NotApplicableCount"] >= by_state.get("NotApplicable", 0), (
        f"NotApplicableCount ({state['NotApplicableCount']}) must be at least the "
        f"{by_state.get('NotApplicable', 0)} NotApplicable records returned by name"
    )
    # A real host has real installed packages: a scan that inventoried nothing
    # installed did not read an RPM database.
    assert state["InstalledCount"] > 0, (
        f"a scan of a real Amazon Linux host must find installed patches; summary was "
        f"{ {k: state.get(k) for k in _counter_keys} !r}"
    )
    assert len(patches) == sum(by_state.values()), "record tally lost a record"

    # --- a patch group that was never registered resolves to no baseline ----
    unregistered = ctx.unique_name("sim2real-behav-pg-none-")
    # An unregistered patch group falls back to the default baseline rather than erroring.
    fallback = ssm.get_patch_baseline_for_patch_group(
        PatchGroup=unregistered, OperatingSystem=_OS
    )
    assert not fallback["BaselineId"].endswith(baseline_id.rsplit("/", 1)[-1]), (
        "a patch group that was never registered must NOT resolve to this check's baseline; "
        f"got {fallback['BaselineId']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
