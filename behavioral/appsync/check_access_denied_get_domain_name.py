"""access-denied-get-domain-name."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "access-denied-get-domain-name"
GROUP = "overly-permissive"
SERVICES = ["appsync"]


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """An explicit Deny on appsync:GetDomainName turns an appsync:* role's NotFoundException into
    AccessDeniedException (explicit-deny message); removing the Deny restores NotFoundException.
    """
    domain_name = f"{ctx.unique_name('sim2real-appsync-')}.example.com"
    iam = ctx.client("iam")
    role_name, restricted, session_arn = _create_restricted_appsync_client(ctx, iam)
    account_id = session_arn.split(":")[4]
    not_found = ("NotFoundException", "Domain name not found")
    explicit_deny = (
        "AccessDeniedException",
        f"User: {session_arn} is not authorized to perform: appsync:GetDomainName on resource: "
        f"arn:aws:appsync:{ctx.region}:{account_id}:domainnames/{domain_name} "
        "with an explicit deny in an identity-based policy",
    )

    def _probe():
        return _error(lambda: restricted.get_domain_name(domainName=domain_name))

    def _poll(expected, description, timeout_s=180, interval_s=5):
        """Poll until the probe returns exactly ``expected`` (code, message); raise on timeout."""
        deadline = time.monotonic() + timeout_s
        seen = None
        while time.monotonic() < deadline:
            seen = _probe()
            if seen == expected:
                return seen
            time.sleep(interval_s)
        raise AssertionError(f"{description} not observed within {timeout_s}s; last saw {seen}")

    before = _poll(not_found, "the Allow-only role reaching the service layer (NotFoundException)")
    assert before == not_found, (
        f"the identity policy grants appsync:GetDomainName, so the real call must reach the "
        f"service layer (NotFoundException) before any Deny is attached, got {before}"
    )

    # A freshly attached IAM statement takes effect with a lag, so the Deny is polled for.
    deny_policy_name = "deny-policy"
    deny_doc = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Deny", "Action": ["appsync:GetDomainName"], "Resource": "*"}],
    }
    iam.put_role_policy(
        RoleName=role_name, PolicyName=deny_policy_name, PolicyDocument=json.dumps(deny_doc)
    )
    ctx.on_cleanup(lambda: _delete_role_policy_if_present(iam, role_name, deny_policy_name))

    denied = _poll(explicit_deny, "AccessDeniedException after the Deny")
    assert denied == explicit_deny, f"expected {explicit_deny}, got {denied}"

    # The unrestricted caller fails only on lookup, so the AccessDenied is not about the domain.
    admin = ctx.client("appsync")
    control_code, control_message = _error(lambda: admin.get_domain_name(domainName=domain_name))
    assert control_code == "NotFoundException", (
        f"expected the unrestricted principal to fail on resource lookup "
        f"(NotFoundException) for a non-existent domain, got {control_code}"
    )
    assert control_message == "Domain name not found", control_message

    iam.delete_role_policy(RoleName=role_name, PolicyName=deny_policy_name)
    restored = _poll(not_found, "NotFoundException restored after removing the Deny")
    assert restored == not_found, (
        f"removing the Deny must restore the pre-Deny outcome (NotFoundException) on the same "
        f"call from the same principal, got {restored}"
    )



def _error(fn):
    """Call fn(); return the (code, message) of its ClientError. An unexpected success raises."""
    try:
        result = fn()
    except ClientError as e:
        err = e.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED with {result!r}")


def _delete_role_policy_if_present(iam, role_name, policy_name):
    try:
        iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
    except ClientError as e:
        if e.response.get("Error", {}).get("Code") != "NoSuchEntity":
            raise


def _create_restricted_appsync_client(ctx, iam):
    """Create an IAM role that can be assumed by the caller's own account, grant it
    appsync:* (nothing else), assume it, and return the role name, an appsync client on the
    same target using those restricted credentials, and the assumed-role session ARN."""
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    role_name = ctx.unique_name("sim2real-appsync-deny-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
            "Action": "sts:AssumeRole",
        }],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    allow_policy_name = "allow-policy"
    allow_doc = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "appsync:*", "Resource": "*"}],
    }
    iam.put_role_policy(
        RoleName=role_name, PolicyName=allow_policy_name, PolicyDocument=json.dumps(allow_doc)
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=allow_policy_name))

    deadline = time.monotonic() + 30
    last_err = None
    while time.monotonic() < deadline:
        try:
            assumed = sts.assume_role(RoleArn=role_arn, RoleSessionName="sim2real-behav")
            creds = assumed["Credentials"]
            client = ctx.client("appsync", creds={
                "aws_access_key_id": creds["AccessKeyId"],
                "aws_secret_access_key": creds["SecretAccessKey"],
                "aws_session_token": creds["SessionToken"],
            })
            return role_name, client, assumed["AssumedRoleUser"]["Arn"]
        except ClientError as e:
            last_err = e
            time.sleep(2)
    raise AssertionError(f"could not assume restricted role in time: {last_err}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
