"""put-compliance-items-limit-exceeded-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-compliance-items-limit-exceeded-rejected"
GROUP = "error-semantics"
SERVICES = ["ssm"]

_AMI_PARAM = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
_SSM_CORE_POLICY_ARN = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
_ALLOW_POLICY_NAME = "allow-put-compliance-items"


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutComplianceItems on a managed node is gated by an ssm:PutComplianceItems grant.

    Without the grant the call fails AccessDeniedException with the exact IAM message and writes
    nothing; with it, the write lands and is listed by ListComplianceItems."""
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    admin_ssm = ctx.client("ssm")
    account_id = sts.get_caller_identity()["Account"]

    resource_id = _provision_connected_target(ctx)
    # Reuse a registered Custom: sub-type; the account caps distinct sub-type names.
    compliance_type = _pick_reusable_custom_compliance_type(admin_ssm) or (
        "Custom:" + ctx.unique_name("S2RIamBoundary").replace("-", "")
    )

    role_name = ctx.unique_name("sim2real-ssm-compliance-bound-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    allow_doc = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "ssm:PutComplianceItems",
                    "Resource": "*",
                }
            ],
        }
    )
    iam.put_role_policy(RoleName=role_name, PolicyName=_ALLOW_POLICY_NAME, PolicyDocument=allow_doc)
    ctx.on_cleanup(lambda: _drop_role_policy(iam, role_name, _ALLOW_POLICY_NAME))

    session_name = ctx.unique_name("sim2real-session-")
    creds = _assume_role_with_retry(sts, iam.get_role(RoleName=role_name)["Role"]["Arn"], session_name)
    restricted_ssm = ctx.client(
        "ssm",
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )

    def _put(item_id: str):
        return restricted_ssm.put_compliance_items(
            ResourceId=resource_id,
            ResourceType="ManagedInstance",
            ComplianceType=compliance_type,
            ExecutionSummary={"ExecutionTime": time.time()},
            Items=[{"Id": item_id, "Title": "check", "Severity": "MEDIUM", "Status": "COMPLIANT"}],
        )

    def _has_item(item_id: str) -> bool:
        items = admin_ssm.list_compliance_items(
            ResourceIds=[resource_id],
            Filters=[{"Key": "ComplianceType", "Values": [compliance_type]}],
        )["ComplianceItems"]
        return any(i["Id"] == item_id for i in items)

    control_id = "control-item"
    _poll_until(
        lambda: _error_code(lambda: _put(control_id)),
        lambda c: c == "UNEXPECTED_SUCCESS",
        timeout_s=_budget_s(ctx, 90.0),
        interval_s=2.0,
        description="the identity policy becomes effective for ssm:PutComplianceItems",
        ctx=ctx,
    )
    assert _poll_until(
        lambda: _has_item(control_id),
        lambda present: present,
        timeout_s=_budget_s(ctx, 60.0),
        interval_s=2.0,
        description="the control write becomes visible via an independent ListComplianceItems read",
        ctx=ctx,
    ), f"control item {control_id!r} must be visible via ListComplianceItems after a granted write"

    _drop_role_policy(iam, role_name, _ALLOW_POLICY_NAME)
    broken_id = "break-item"
    denied = _poll_until(
        lambda: _error_code(lambda: _put(broken_id)),
        lambda c: c == "AccessDeniedException",
        timeout_s=_budget_s(ctx, 90.0),
        interval_s=2.0,
        description="removing the grant refuses ssm:PutComplianceItems with AccessDeniedException",
        ctx=ctx,
    )
    assert denied == "AccessDeniedException", (
        f"the identical call must be refused with AccessDeniedException once the grant is "
        f"removed; got {denied!r}"
    )
    denied_message = _error_message(lambda: _put(broken_id))
    assert denied_message == (
        f"User: arn:aws:sts::{account_id}:assumed-role/{role_name}/{session_name} is not "
        f"authorized to perform: ssm:PutComplianceItems on resource: "
        f"arn:aws:ec2:{ctx.region}:{account_id}:instance/{resource_id} because no "
        f"identity-based policy allows the ssm:PutComplianceItems action"
    ), (
        f"unexpected AccessDeniedException message {denied_message!r}"
    )

    assert not _has_item(broken_id), (
        f"item {broken_id!r} must be ABSENT via ListComplianceItems -- the denied call must "
        f"never have written it"
    )

    iam.put_role_policy(RoleName=role_name, PolicyName=_ALLOW_POLICY_NAME, PolicyDocument=allow_doc)
    restored = _poll_until(
        lambda: _error_code(lambda: _put(broken_id)),
        lambda c: c == "UNEXPECTED_SUCCESS",
        timeout_s=_budget_s(ctx, 90.0),
        interval_s=2.0,
        description="restoring the grant lets the identical call succeed again",
        ctx=ctx,
    )
    assert restored == "UNEXPECTED_SUCCESS", (
        f"restoring the grant must let the identical PutComplianceItems call succeed again; "
        f"got {restored!r}"
    )

    assert _poll_until(
        lambda: _has_item(broken_id),
        lambda present: present,
        timeout_s=_budget_s(ctx, 60.0),
        interval_s=2.0,
        description="the restored write becomes visible via an independent ListComplianceItems read",
        ctx=ctx,
    ), f"item {broken_id!r} must be visible via ListComplianceItems once the grant is restored"


def _drop_role_policy(iam, role_name: str, policy_name: str) -> None:
    try:
        iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NoSuchEntity":
            raise


def _pick_reusable_custom_compliance_type(ssm) -> str | None:
    """An already-registered Custom: sub-type of AWS:ComplianceItem, if one exists in-account."""
    resp = ssm.get_inventory_schema(TypeName="AWS:ComplianceItem", SubType=True)
    for schema in resp.get("Schemas", []):
        name = schema.get("TypeName", "")
        if name.startswith("Custom:"):
            return name
    return None


def _provision_connected_target(ctx) -> str:
    """Launch one EC2 instance with AmazonSSMManagedInstanceCore; wait until it is Online in SSM."""
    iam = ctx.client("iam")
    ec2 = ctx.client("ec2")
    ssm = ctx.client("ssm")

    role_name = ctx.unique_name("sim2real-behav-ssm-role-")
    trust_policy = json.dumps(
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
    )
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=trust_policy,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.attach_role_policy(RoleName=role_name, PolicyArn=_SSM_CORE_POLICY_ARN)
    ctx.on_cleanup(
        lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=_SSM_CORE_POLICY_ARN)
    )

    profile_name = ctx.unique_name("sim2real-behav-ssm-profile-")
    iam.create_instance_profile(InstanceProfileName=profile_name)
    ctx.on_cleanup(lambda: iam.delete_instance_profile(InstanceProfileName=profile_name))
    iam.add_role_to_instance_profile(InstanceProfileName=profile_name, RoleName=role_name)
    ctx.on_cleanup(
        lambda: iam.remove_role_from_instance_profile(
            InstanceProfileName=profile_name, RoleName=role_name
        )
    )

    ami_id = ssm.get_parameter(Name=_AMI_PARAM)["Parameter"]["Value"]
    name_tag = ctx.unique_name("sim2real-behav-ssm-target-")

    instance_id = None
    last_err = None
    deadline = time.monotonic() + _budget_s(ctx, 90)
    while instance_id is None and time.monotonic() < deadline:
        try:
            run_resp = ec2.run_instances(
                ImageId=ami_id,
                InstanceType="t3.micro",
                MinCount=1,
                MaxCount=1,
                IamInstanceProfile={"Name": profile_name},
                TagSpecifications=[
                    {"ResourceType": "instance", "Tags": [{"Key": "Name", "Value": name_tag}]}
                ],
                SubnetId=ctx.network().subnet_ids[0],
            )
            instance_id = run_resp["Instances"][0]["InstanceId"]
        except ClientError as exc:
            last_err = exc
            if exc.response["Error"]["Code"] not in (
                "InvalidParameterValue",
                "InvalidParameterValueError",
            ):
                raise
            time.sleep(2)
    if instance_id is None:
        if _budget_spent(ctx):
            raise TimeoutError("RunInstances accepting the instance profile: the run budget ended first; "
                               "not graded")
        raise AssertionError(f"run_instances never succeeded after IAM propagation: {last_err}")
    ctx.on_cleanup(lambda: ec2.terminate_instances(InstanceIds=[instance_id]))

    _wait_instances(ec2, [instance_id], "running", _budget_s(ctx, 600.0), ctx=ctx)

    deadline = time.monotonic() + _budget_s(ctx, 600)
    online = False
    while not online and time.monotonic() < deadline:
        info = ssm.describe_instance_information(
            Filters=[{"Key": "InstanceIds", "Values": [instance_id]}]
        )["InstanceInformationList"]
        online = any(i.get("PingStatus") == "Online" for i in info)
        if not online:
            time.sleep(2)
    if not online:
        if _budget_spent(ctx):
            raise TimeoutError(f"instance {instance_id} reaching PingStatus=Online: the run budget ended first; "
                               "not graded")
        raise AssertionError(f"instance {instance_id} never reached SSM PingStatus=Online in time")
    return instance_id


def _assume_role_with_retry(sts, role_arn, session_name, attempts=10, delay_s=2.0):
    """Retry AssumeRole until a new role is assumable; IAM trust propagation lags CreateRole."""
    last_exc = None
    for _ in range(attempts):
        try:
            resp = sts.assume_role(RoleArn=role_arn, RoleSessionName=session_name)
            return resp["Credentials"]
        except ClientError as exc:
            last_exc = exc
            time.sleep(delay_s)
    raise last_exc


def _error_code(fn) -> str:
    """The captured AWS error code, or a sentinel that cannot be mistaken for one on success."""
    try:
        fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code")
    return "UNEXPECTED_SUCCESS"


def _error_message(fn) -> str:
    """Return the AWS error message fn() raises; raise if the call unexpectedly succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Message")
    raise AssertionError(f"expected AccessDeniedException, but the call SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s: float = 30.0, interval_s: float = 1.0, description: str = "condition",
                ctx=None):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError(f"{description}: the run budget ended first; not graded")
    raise AssertionError(f"{description} not reached within {timeout_s}s; last value: {last!r}")


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _wait_instances(ec2, instance_ids, want: str, timeout_s: float, *, strict: bool = True, ctx=None) -> None:
    """Poll every 1 s until every instance is in state want; a strict wait fails on a dead end."""
    dead = {"running": ("shutting-down", "terminated", "stopping", "stopped")}.get(want, ())
    deadline = time.monotonic() + timeout_s
    states = {}
    while True:
        try:
            reservations = ec2.describe_instances(InstanceIds=list(instance_ids))["Reservations"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidInstanceID.NotFound":
                raise
            reservations = []
        states = {i["InstanceId"]: i["State"]["Name"] for r in reservations for i in r["Instances"]}
        if len(states) == len(instance_ids) and all(s == want for s in states.values()):
            return
        if not strict:
            if time.monotonic() >= deadline:
                return
        else:
            assert not any(s in dead for s in states.values()), (
                f"instances {list(instance_ids)} reached {states!r} instead of {want!r}")
            if time.monotonic() >= deadline and ctx is not None and _budget_spent(ctx):
                raise TimeoutError(f"instances reaching {want!r}: the run budget ended first; not graded")
            assert time.monotonic() < deadline, (
                f"instances {list(instance_ids)} not {want!r} in time: {states!r}")
        time.sleep(1.0)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
