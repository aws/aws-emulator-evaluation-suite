"""missing-iam-permission-create-monitor-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "missing-iam-permission-create-monitor-rejected"
GROUP = "overly-permissive"
SERVICES = ["networkmonitor"]


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A role allowed networkmonitor:CreateMonitor creates a monitor; with an explicit Deny added the
    same call fails with AccessDeniedException and the exact message and creates nothing; removing the
    Deny restores success, and the default caller succeeds throughout."""
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    nm = ctx.client("networkmonitor")
    account_id = sts.get_caller_identity()["Account"]

    # Create-or-adopt the service-linked role NetworkMonitor auto-creates on first CreateMonitor.
    # Doing this with the default (admin) identity means the probed role only ever needs
    # networkmonitor:CreateMonitor itself, not the one-time iam:CreateServiceLinkedRole grant a
    # cold account would otherwise demand of it.
    _ensure_service_linked_role(iam, "networkmonitor.amazonaws.com")

    role_name = ctx.unique_name("sim2real-nm-deny-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
            "Action": "sts:AssumeRole",
        }],
    }
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=_json(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    allow_policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "networkmonitor:CreateMonitor", "Resource": "*"}],
    }
    allow_policy_name = ctx.unique_name("sim2real-nm-allow-policy-")
    iam.put_role_policy(RoleName=role_name, PolicyName=allow_policy_name, PolicyDocument=_json(allow_policy))
    ctx.on_cleanup(lambda: _delete_role_policy_ignore_missing(iam, role_name, allow_policy_name))

    deny_policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Deny", "Action": "networkmonitor:CreateMonitor", "Resource": "*"}],
    }
    deny_policy_name = ctx.unique_name("sim2real-nm-deny-policy-")

    role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"
    session_name = "sim2real-nm-session"
    creds = _assume_role_with_retry(sts, role_arn, session_name)
    probe_nm = _client_from_creds(ctx, creds)

    def _try_create(name):
        return _error(lambda: probe_nm.create_monitor(monitorName=name, aggregationPeriod=30))

    # Positive control: the role's own allow grants CreateMonitor, before any Deny exists.
    (before_code, _), before_name = _poll_create_until(
        ctx, nm, _try_create, "sim2real-nm-before-", lambda c: c[0] == "UNEXPECTED_SUCCESS",
        timeout_s=60, description="the role's allow grant becomes effective for CreateMonitor",
    )
    assert before_code == "UNEXPECTED_SUCCESS", (
        f"the role policy grants networkmonitor:CreateMonitor, so the call must succeed before "
        f"any deny is attached; got {before_code!r}"
    )

    # Break exactly one thing: an explicit Deny on top of the existing allow.
    iam.put_role_policy(RoleName=role_name, PolicyName=deny_policy_name, PolicyDocument=_json(deny_policy))
    ctx.on_cleanup(lambda: _delete_role_policy_ignore_missing(iam, role_name, deny_policy_name))

    (denied_code, denied_message), denied_name = _poll_create_until(
        ctx, nm, _try_create, "sim2real-nm-denied-", lambda c: c[0] == "AccessDeniedException",
        timeout_s=300, description="the explicit deny becomes effective for CreateMonitor",
    )
    assert denied_code == "AccessDeniedException", f"expected AccessDeniedException, got {denied_code!r}"
    expected_denied = (
        f"User: arn:aws:sts::{account_id}:assumed-role/{role_name}/{session_name} is not authorized "
        f"to perform: networkmonitor:CreateMonitor on resource: "
        f"arn:aws:networkmonitor:{ctx.region}:{account_id}:monitor/{denied_name} "
        f"with an explicit deny in an identity-based policy"
    )
    assert denied_message == expected_denied, f"expected message {expected_denied!r}, got {denied_message!r}"

    # Effect absent: the denied call must not have created the resource under any identity.
    code_lookup, lookup_message = _error(lambda: nm.get_monitor(monitorName=denied_name))
    assert code_lookup == "ResourceNotFoundException", (
        f"denied CreateMonitor must not have created the resource, lookup gave {code_lookup!r}"
    )
    expected_lookup = f"No existing monitor found for account {account_id} and monitorName {denied_name}."
    assert lookup_message == expected_lookup, f"expected message {expected_lookup!r}, got {lookup_message!r}"

    # Restore: remove the Deny, the identical call on the SAME identity now succeeds again.
    _delete_role_policy_ignore_missing(iam, role_name, deny_policy_name)
    (restored_code, _), restored_name = _poll_create_until(
        ctx, nm, _try_create, "sim2real-nm-restored-", lambda c: c[0] == "UNEXPECTED_SUCCESS",
        timeout_s=300, description="removing the deny restores CreateMonitor for the same identity",
    )
    assert restored_code == "UNEXPECTED_SUCCESS", (
        f"removing the deny must restore networkmonitor:CreateMonitor for the same role; "
        f"got {restored_code!r}"
    )

    # Independent read at the destination, through a different operation than the create.
    restored = nm.get_monitor(monitorName=restored_name)
    assert restored["monitorName"] == restored_name, (
        f"the monitor created after restore must be independently readable by name; "
        f"got {restored.get('monitorName')!r}"
    )

    # Positive control: the default (permitted) caller identity succeeds throughout, and its
    # effect is confirmed by an independent read too.
    good_name = ctx.unique_name("sim2real-nm-allowed-")
    nm.create_monitor(monitorName=good_name, aggregationPeriod=30, tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: nm.delete_monitor(monitorName=good_name))
    fetched = nm.get_monitor(monitorName=good_name)
    assert fetched["monitorName"] == good_name, (
        f"the default identity's monitor must be independently readable by name; "
        f"got {fetched.get('monitorName')!r}"
    )


def _json(obj):
    import json

    return json.dumps(obj)


def _error(fn):
    """The captured AWS error (code, message), or a sentinel code that cannot be mistaken for one
    on success."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    return "UNEXPECTED_SUCCESS", None


def _ensure_service_linked_role(iam, aws_service_name):
    from botocore.exceptions import ClientError

    try:
        iam.create_service_linked_role(AWSServiceName=aws_service_name)
    except ClientError as e:
        if e.response["Error"]["Code"] != "InvalidInput":
            raise


def _poll_create_until(ctx, nm, try_create, name_prefix, predicate, *, timeout_s, interval_s=3.0, description="condition"):
    """Retry a CreateMonitor probe with a FRESH name each attempt (Create is not idempotent under
    retry) until predicate(code) holds. Any UNEXPECTED_SUCCESS registers cleanup immediately, so a
    stray early success on a losing attempt is never left behind."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        name = ctx.unique_name(name_prefix)
        code = try_create(name)
        if code[0] == "UNEXPECTED_SUCCESS":
            ctx.on_cleanup(lambda n=name: nm.delete_monitor(monitorName=n))
        last = (code, name)
        if predicate(code):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not observed within {timeout_s}s; last saw {last!r}")


def _delete_role_policy_ignore_missing(iam, role_name, policy_name):
    from botocore.exceptions import ClientError

    try:
        iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
    except ClientError as e:
        if e.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _assume_role_with_retry(sts, role_arn, session_name, timeout_s=60.0, interval_s=5.0):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_error = None
    while time.monotonic() < deadline:
        try:
            resp = sts.assume_role(RoleArn=role_arn, RoleSessionName=session_name)
            return resp["Credentials"]
        except ClientError as e:
            last_error = e
            time.sleep(interval_s)
    raise AssertionError(f"could not assume role {role_arn} within {timeout_s}s: {last_error}")


def _client_from_creds(ctx, creds):
    return ctx.client("networkmonitor", creds={
        "aws_access_key_id": creds["AccessKeyId"],
        "aws_secret_access_key": creds["SecretAccessKey"],
        "aws_session_token": creds["SessionToken"],
    })

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
