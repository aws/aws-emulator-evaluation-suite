"""account-summary-server-side-aggregation-reflects-resource-counts."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "account-summary-server-side-aggregation-reflects-resource-counts"
GROUP = "server-side"
SERVICES = ["iam"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetAccountSummary's resource counters (Users, Roles, MFADevices) are recomputed
    server-side automatically as a side effect of CreateUser/CreateRole/
    CreateVirtualMFADevice -- no explicit recompute/refresh call exists or is needed."""
    iam = ctx.client("iam")

    baseline = iam.get_account_summary()["SummaryMap"]
    baseline_users = baseline.get("Users", 0)
    baseline_roles = baseline.get("Roles", 0)
    baseline_mfa = baseline.get("MFADevices", 0)

    username = ctx.unique_name("sim2real-acctsum-user-")
    rolename = ctx.unique_name("sim2real-acctsum-role-")
    device_name = ctx.unique_name("sim2real-acctsum-mfa-")

    resource_tags = [{"Key": "sim2real", "Value": CHECK}]

    iam.create_user(UserName=username, Tags=resource_tags)
    ctx.on_cleanup(lambda: iam.delete_user(UserName=username))

    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    iam.create_role(RoleName=rolename, AssumeRolePolicyDocument=json.dumps(trust_policy), Tags=resource_tags)
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=rolename))

    serial = iam.create_virtual_mfa_device(VirtualMFADeviceName=device_name, Tags=resource_tags)[
        "VirtualMFADevice"
    ]["SerialNumber"]
    ctx.on_cleanup(lambda: iam.delete_virtual_mfa_device(SerialNumber=serial))

    deadline = time.monotonic() + 30.0
    final_summary = None
    while time.monotonic() < deadline:
        final_summary = iam.get_account_summary()["SummaryMap"]
        if (
            final_summary.get("Users", 0) >= baseline_users + 1
            and final_summary.get("Roles", 0) >= baseline_roles + 1
            and final_summary.get("MFADevices", 0) >= baseline_mfa + 1
        ):
            break
        time.sleep(1.5)

    assert final_summary is not None, "get_account_summary never returned before the poll deadline"
    assert final_summary.get("Users", 0) >= baseline_users + 1, (
        f"Users counter did not reflect the new user: {baseline_users} -> {final_summary.get('Users')}"
    )
    assert final_summary.get("Roles", 0) >= baseline_roles + 1, (
        f"Roles counter did not reflect the new role: {baseline_roles} -> {final_summary.get('Roles')}"
    )
    assert final_summary.get("MFADevices", 0) >= baseline_mfa + 1, (
        f"MFADevices counter did not reflect the new device: {baseline_mfa} -> {final_summary.get('MFADevices')}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
