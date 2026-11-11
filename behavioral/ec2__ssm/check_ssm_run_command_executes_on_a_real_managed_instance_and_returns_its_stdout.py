"""ssm-run-command-executes-on-a-real-managed-instance-and-returns-its-stdout."""
from __future__ import annotations

import json
import sys
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "ssm-run-command-executes-on-a-real-managed-instance-and-returns-its-stdout"
GROUP = 'run-command'
SERVICES = ['ec2', 'ssm']

_SEED = 41
_AL2023_AMI_PARAM = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
_SSM_CORE_POLICY = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
_INSTANCE_TYPE = "t3.micro"
_TERMINAL = ("Success", "Cancelled", "TimedOut", "Failed")
_GONE = ("InvalidInstanceID.NotFound",)
_THROTTLE = ("Throttling", "ThrottlingException", "RequestLimitExceeded", "TooManyUpdates")


def _error(fn):
    """Return (code, message) of the ClientError fn raises; raise AssertionError if it succeeds."""
    try:
        resp = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"the call was expected to be refused and succeeded: {resp!r}")


def _param_name(ctx, suffix=""):
    # SSM requires a leading '/' for any hierarchical (slash-containing) name.
    return "/" + ctx.unique_name("sim2real-behav-" + suffix)


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


def _poll(probe, predicate, timeout_s, interval_s=5.0, what=""):
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{what or 'condition'} not met within {timeout_s}s (last observed: {last!r})"
            )
        time.sleep(interval_s)


def _usable_zone(ec2, within):
    """An AZ of `within` that both is available and offers the instance type. No hardcoded zone."""
    offered = {
        o["Location"]
        for o in ec2.describe_instance_type_offerings(
            LocationType="availability-zone",
            Filters=[{"Name": "instance-type", "Values": [_INSTANCE_TYPE]}],
        )["InstanceTypeOfferings"]
    }
    available = {
        z["ZoneName"]
        for z in ec2.describe_availability_zones(
            Filters=[{"Name": "state", "Values": ["available"]},
                     {"Name": "zone-type", "Values": ["availability-zone"]}]
        )["AvailabilityZones"]
    }
    usable = sorted(offered & available & set(within))
    assert usable, (
        f"no available AZ in this region offers {_INSTANCE_TYPE}; offered {sorted(offered)!r}, "
        f"available {sorted(available)!r}"
    )
    return usable[0]


def _build_network(ctx, ec2, st):
    """Place the host in a public subnet of the run's shared network (internet route, public
    addresses on launch), in a zone that offers the instance type."""
    shared = ctx.network()
    st["zone"] = _usable_zone(ec2, shared.availability_zones)
    st["subnet"] = shared.subnets[st["zone"]]


def _teardown_network(ec2, st, timeout_s=600):
    """Waiting teardown, IN BAND: the cleanup join is bounded at 60 s and an instance takes
    longer than that to terminate. Raises what it could not remove, carrying any failure in
    flight. All steps share one ``timeout_s`` deadline."""
    deadline = time.monotonic() + timeout_s

    def _remaining() -> float:
        return max(0.0, deadline - time.monotonic())

    left = []
    steps = []

    def _try(label, fn):
        steps.append((label, fn))

    if st.get("instance"):
        _try(f"terminate {st['instance']}",
             lambda: _terminate_and_wait(ec2, st["instance"], _remaining()))
    for label, fn in steps:
        try:
            fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code not in _GONE:
                left.append(f"{label}: {code}")
        except AssertionError as exc:
            left.append(f"{label}: {str(exc)[:160]}")
    if left:
        found = sys.exc_info()[1]
        raise AssertionError(
            (f"{found!r}; " if found else "")
            + f"teardown could not remove everything the check created: {left!r}"
        )


def _terminate_and_wait(ec2, instance_id, timeout_s=300):
    """Terminate and wait until the instance is terminated, so its ENI leaves the subnet and the
    instance profile it references can be deleted. Raises on timeout."""
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
        if all(s == "terminated" for s in states):
            return
        time.sleep(5)
    raise AssertionError(f"instance {instance_id} not terminated within {timeout_s}s")


def _drop_instance_profile(iam, profile_name, role_name):
    for attempt in range(12):
        try:
            iam.remove_role_from_instance_profile(
                InstanceProfileName=profile_name, RoleName=role_name
            )
            break
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") in ("NoSuchEntity",):
                break
            if attempt == 11:
                raise
            time.sleep(5)
    for attempt in range(12):
        try:
            iam.delete_instance_profile(InstanceProfileName=profile_name)
            return
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") in ("NoSuchEntity",):
                return
            if attempt == 11:
                raise
            time.sleep(5)


def _drop_role(iam, role_name, inline_policy):
    for arn in (_SSM_CORE_POLICY,):
        try:
            iam.detach_role_policy(RoleName=role_name, PolicyArn=arn)
        except ClientError as err:
            if err.response["Error"]["Code"] != "NoSuchEntity":
                raise
    try:
        iam.delete_role_policy(RoleName=role_name, PolicyName=inline_policy)
    except ClientError as err:
        if err.response["Error"]["Code"] != "NoSuchEntity":
            raise
    for attempt in range(12):
        try:
            iam.delete_role(RoleName=role_name)
            return
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") in ("NoSuchEntity",):
                return
            if attempt == 11:
                raise
            time.sleep(5)


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
    """A shell command sent to a real SSM-managed EC2 instance reads a parameter with the host's
    profile credentials and returns the computed value as stdout, with empty stderr and exit 0;
    the command summary and list form agree, and another instance id has no invocation."""

    ssm = ctx.client("ssm")
    ec2 = ctx.client("ec2")
    iam = ctx.client("iam")

    # --- the value the host will have to fetch and compute over ---------------
    param = _param_name(ctx, "runcmd-src-")
    ssm.put_parameter(
        Name=param,
        Value=str(_SEED),
        Type="String",
        Tags=[{"Key": "sim2real", "Value": "run-command-stdout"}],
    )
    ctx.on_cleanup(lambda: ssm.delete_parameter(Name=param))

    # --- an instance role that can register with SSM and read that parameter ---
    role_name = ctx.unique_name("sim2real-behav-runcmd-")
    inline_policy = f"{role_name}-param"
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "ec2.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Description="sim2real-behav run-command managed instance role",
        Tags=[{"Key": "sim2real", "Value": "run-command-stdout"}],
    )
    ctx.on_cleanup(lambda: _drop_role(iam, role_name, inline_policy))
    iam.attach_role_policy(RoleName=role_name, PolicyArn=_SSM_CORE_POLICY)
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=inline_policy,
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "ssm:GetParameter",
                        "Resource": "*",
                    }
                ],
            }
        ),
    )

    profile_name = role_name
    iam.create_instance_profile(
        InstanceProfileName=profile_name,
        Tags=[{"Key": "sim2real", "Value": "run-command-stdout"}],
    )
    ctx.on_cleanup(lambda: _drop_instance_profile(iam, profile_name, role_name))
    iam.add_role_to_instance_profile(
        InstanceProfileName=profile_name, RoleName=role_name
    )

    st = {}
    try:
        # --- launch one instance under the agent ---------------------------------
        ami = ssm.get_parameter(Name=_AL2023_AMI_PARAM)["Parameter"]["Value"]
        _build_network(ctx, ec2, st)
        subnet_id, zone = st["subnet"], st["zone"]
        tag_spec = [
            {
                "ResourceType": rt,
                "Tags": [
                    {"Key": "Name", "Value": role_name},
                    {"Key": "sim2real", "Value": "run-command-stdout"},
                ],
            }
            for rt in ("instance", "volume")
        ]
        # A brand-new instance profile is not immediately resolvable by RunInstances.
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
            retries=30,
            delay=5.0,
        )
        instance_id = reservation["Instances"][0]["InstanceId"]
        # Recorded BEFORE the registration poll: the in-band teardown terminates a host that never
        # comes up, so it cannot strand a billing instance.
        st["instance"] = instance_id
        assert reservation["Instances"][0]["Placement"]["AvailabilityZone"] == zone, (
            f"the instance landed in {reservation['Instances'][0]['Placement']!r}, not {zone!r}"
        )

        # --- the agent must register: a host that never registers is a FAIL -------
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
            interval_s=5.0,
            what=f"the SSM agent on {instance_id} coming Online",
        )
        assert info["PingStatus"] == "Online", f"instance {instance_id!r} is {info!r}"
        assert info["ResourceType"] == "EC2Instance", info
        # Facts only a running agent on a real host can report. `IamRole` is not one of them:
        # it is absent for an EC2-registered node (it is the role of a hybrid-activation node).
        assert info["PlatformType"] == "Linux", (
            f"an AL2023 host must register as PlatformType Linux, got {info.get('PlatformType')!r}"
        )
        assert info.get("AgentVersion"), (
            f"a registered node must report the agent version running on it, got {info!r}"
        )
        assert info.get("ComputerName"), (
            f"a registered node must report the host's own computer name, got {info!r}"
        )
        assert info.get("IsLatestVersion") is not None, (
            f"a registered node must report whether its agent is current, got {info!r}"
        )

        # --- the command: the HOST fetches the parameter and computes ------------
        expected_stdout = str(_SEED * 5 + 2)
        script = [
            "set -euo pipefail",
            f"V=$(aws ssm get-parameter --name {param} --query Parameter.Value "
            f"--output text --region {ctx.region})",
            'echo "$(( V * 5 + 2 ))"',
        ]
        sent = _call_with_retry(
            lambda: ssm.send_command(
                InstanceIds=[instance_id],
                DocumentName="AWS-RunShellScript",
                Parameters={"commands": script},
                TimeoutSeconds=120,
                Comment="sim2real-behav run-command stdout",
            )
        )
        command_id = sent["Command"]["CommandId"]
        assert sent["Command"]["Status"] == "Pending", (
            f"a freshly accepted command must be Pending, got {sent['Command']['Status']!r}"
        )

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
            timeout_s=180,
            interval_s=5.0,
            what=f"invocation {command_id} reaching a terminal status",
        )

        assert inv["Status"] == "Success", (
            f"the invocation was {inv['Status']!r}: {inv.get('StatusDetails')!r} "
            f"stderr={inv.get('StandardErrorContent')!r}"
        )
        assert inv["ResponseCode"] == 0, f"ResponseCode was {inv['ResponseCode']!r}"
        assert inv["StandardOutputContent"].strip() == expected_stdout, (
            "the host must have read the parameter through its instance profile and computed "
            f"{expected_stdout!r}; stdout was {inv['StandardOutputContent']!r}"
        )
        assert inv["StandardErrorContent"] == "", (
            f"the script wrote to stderr: {inv['StandardErrorContent']!r}"
        )
        assert inv["InstanceId"] == instance_id, (
            f"the invocation reports instance {inv['InstanceId']!r}, expected {instance_id!r}"
        )
        assert inv["DocumentName"] == "AWS-RunShellScript", inv

        # --- the command summary must aggregate the one target -------------------
        cmd = _poll(
            lambda: _call_with_retry(
                lambda: ssm.list_commands(CommandId=command_id)["Commands"][0]
            ),
            lambda c: c.get("Status") in _TERMINAL,
            timeout_s=120,
            interval_s=5.0,
            what="the command summary reaching a terminal status",
        )
        assert (cmd["TargetCount"], cmd["CompletedCount"], cmd["ErrorCount"]) == (1, 1, 0), (
            "the command counters must report one target completed with no errors; got "
            f"{(cmd['TargetCount'], cmd['CompletedCount'], cmd['ErrorCount'])!r}"
        )
        assert cmd["Status"] == "Success", f"the command summary was {cmd['Status']!r}"

        # --- the invocation is also findable through the list form, and agrees ---
        listed = []
        for page in ssm.get_paginator("list_command_invocations").paginate(
            CommandId=command_id, Details=True
        ):
            listed += page["CommandInvocations"]
        assert len(listed) == 1, (
            f"exactly one invocation must exist for a single-target command, got {listed!r}"
        )
        assert listed[0]["InstanceId"] == instance_id, listed[0]
        assert listed[0]["Status"] == "Success", listed[0]

        # --- negative: the same command id against another instance id has no ----
        # invocation, so the output above is attributed to this host and not global.
        stray_code, stray_message = _error(
            lambda: ssm.get_command_invocation(
                CommandId=command_id, InstanceId="i-00000000000000000"
            )
        )
        assert stray_code == "InvocationDoesNotExist", (
            "an invocation must exist only for the instance it targeted; asking for another "
            f"instance id must be refused, got {stray_code!r}"
        )
        assert stray_message == f"Invocation not found for {command_id}, i-00000000000000000", (
            f"GetCommandInvocation refusal message was {stray_message!r}"
        )

    finally:
        _teardown_network(ec2, st)

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
