"""acme-external-account-binding-full-lifecycle."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "acme-external-account-binding-full-lifecycle"
GROUP = "state-machine"
SERVICES = ["acm"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateAcmeExternalAccountBinding produces a binding queryable via Describe/List/GetCredentials,
    revocable, then deletable; a deleted binding rejects further mutation with ResourceNotFoundException.
    """
    acm = ctx.client("acm")
    endpoint_arn = _create_active_endpoint(ctx, acm)
    role_arn = _create_acme_role(ctx)

    created = _create_binding_once_role_passable(acm, endpoint_arn, role_arn)
    eab_arn = created["AcmeExternalAccountBindingArn"]
    # The binding's ARN nests under its endpoint's: <endpoint-arn>/acme-external-account-binding/<id>.
    assert eab_arn.startswith(f"{endpoint_arn}/acme-external-account-binding/"), f"unexpected EAB arn shape: {eab_arn}"
    assert created["RoleArn"] == role_arn, f"expected RoleArn {role_arn}, got {created['RoleArn']}"
    assert created["AcmeEndpointArn"] == endpoint_arn, (
        f"expected AcmeEndpointArn {endpoint_arn}, got {created['AcmeEndpointArn']}"
    )
    assert "RevokedAt" not in created or created["RevokedAt"] is None, (
        f"freshly created EAB must not be revoked, got RevokedAt={created.get('RevokedAt')!r}"
    )

    cleanup_state = {"eab_deleted": False}

    def _cleanup_eab():
        if not cleanup_state["eab_deleted"]:
            _ignore_not_found(lambda: acm.delete_acme_external_account_binding(AcmeExternalAccountBindingArn=eab_arn))

    ctx.on_cleanup(_cleanup_eab)

    # Visible via Describe.
    desc = acm.describe_acme_external_account_binding(AcmeExternalAccountBindingArn=eab_arn)["ExternalAccountBinding"]
    assert desc["RoleArn"] == role_arn, f"describe: expected RoleArn {role_arn}, got {desc['RoleArn']}"
    assert desc.get("ExpiresAt") is not None, f"describe: expected ExpiresAt to be set, got {desc.get('ExpiresAt')!r}"

    # Visible via List scoped to the endpoint.
    assert _find_eab(acm, endpoint_arn, eab_arn) is not None, "binding missing from ListAcmeExternalAccountBindings"

    # Credentials are retrievable and non-trivial.
    creds = acm.get_acme_external_account_binding_credentials(AcmeExternalAccountBindingArn=eab_arn)
    assert isinstance(creds["KeyId"], str) and len(creds["KeyId"]) > 0, f"expected non-empty KeyId, got {creds.get('KeyId')!r}"
    assert isinstance(creds["MacKey"], str) and len(creds["MacKey"]) > 0, (
        f"expected non-empty MacKey, got {creds.get('MacKey')!r}"
    )

    # Revocable.
    acm.revoke_acme_external_account_binding(AcmeExternalAccountBindingArn=eab_arn)
    desc2 = acm.describe_acme_external_account_binding(AcmeExternalAccountBindingArn=eab_arn)["ExternalAccountBinding"]
    assert desc2.get("RevokedAt") is not None, "RevokedAt not set after RevokeAcmeExternalAccountBinding"

    # Deletable.
    acm.delete_acme_external_account_binding(AcmeExternalAccountBindingArn=eab_arn)
    cleanup_state["eab_deleted"] = True
    removed = _poll_until_removed(
        lambda: acm.describe_acme_external_account_binding(AcmeExternalAccountBindingArn=eab_arn), timeout_s=60
    )
    assert removed, "binding was not removed after DeleteAcmeExternalAccountBinding"

    # A mutation on the now-dead binding id must also fail, with the same specific code.
    revoke_dead_code, revoke_dead_message = _error(
        lambda: acm.revoke_acme_external_account_binding(AcmeExternalAccountBindingArn=eab_arn)
    )
    assert revoke_dead_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException revoking a deleted EAB, got {revoke_dead_code}"
    )
    assert revoke_dead_message == f"Could not find ACME external account binding {eab_arn}.", revoke_dead_message

    # The endpoint the binding lived on still deletes cleanly.
    acm.delete_acme_endpoint(AcmeEndpointArn=endpoint_arn)
    ep_removed = _poll_until_removed(lambda: acm.describe_acme_endpoint(AcmeEndpointArn=endpoint_arn), timeout_s=60)
    assert ep_removed, "endpoint was not removed after DeleteAcmeEndpoint"


def _create_active_endpoint(ctx, acm):
    name = ctx.unique_name("sim2real-behav-acme-ep-")
    arn = acm.create_acme_endpoint(
        AuthorizationBehavior="PRE_APPROVED",
        CertificateAuthority={"PublicCertificateAuthority": {}},
        Contact="NOT_REQUIRED",
        Tags=[{"Key": "Name", "Value": name}],
    )["AcmeEndpointArn"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: acm.delete_acme_endpoint(AcmeEndpointArn=arn)))
    _wait_for_status(acm, arn, {"ACTIVE", "FAILED"}, timeout_s=90)
    return arn


def _create_acme_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-acme-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "acm-acme.amazonaws.com"},
                "Action": ["sts:AssumeRole", "sts:TagSession", "sts:SetSourceIdentity"],
                "Condition": {"StringLikeIfExists": {"sts:SourceIdentity": "acm-acme-*"}},
            }
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "Purpose", "Value": "sim2real-behavioral"}],
    )["Role"]
    role_arn = role["Arn"]
    # Registered in reverse-desired-teardown order: cleanup runs LIFO, so the policy
    # detach (registered second) fires before the role delete (registered first).
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: iam.delete_role(RoleName=role_name)))
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="acme-issue")))
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="acme-issue",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Action": ["acm:RequestCertificate", "acm:RevokeCertificate"], "Resource": "*"}
                ],
            }
        ),
    )
    return role_arn


def _wait_for_status(acm, arn, terminal_statuses, timeout_s=90.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = acm.describe_acme_endpoint(AcmeEndpointArn=arn)["AcmeEndpoint"]["Status"]
        if last in terminal_statuses:
            return last
        time.sleep(interval_s)
    return last


def _error(fn):
    """The (code, message) of the ClientError fn raises, or ("SUCCEEDED", None) when it succeeds."""
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    return "SUCCEEDED", None


def _find_eab(acm, endpoint_arn, eab_arn):
    kwargs = {"AcmeEndpointArn": endpoint_arn}
    while True:
        resp = acm.list_acme_external_account_bindings(**kwargs)
        for b in resp.get("ExternalAccountBindings", []):
            if b.get("AcmeExternalAccountBindingArn") == eab_arn:
                return b
        token = resp.get("NextToken")
        if not token:
            return None
        kwargs = {"AcmeEndpointArn": endpoint_arn, "NextToken": token}


def _poll_until_removed(fn, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if _error(fn)[0] == "ResourceNotFoundException":
            return True
        time.sleep(interval_s)
    return False


def _ignore_not_found(fn):
    """Run a teardown delete; only an already-gone resource is tolerated."""
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("ResourceNotFoundException", "NoSuchEntity"):
            raise


def _create_binding_once_role_passable(acm, endpoint_arn, role_arn, timeout_s=180.0, interval_s=5.0):
    """A freshly created role is briefly not passable to acm-acme (IAM propagation), so
    CreateAcmeExternalAccountBinding is retried on that AccessDenied until the role settles."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return acm.create_acme_external_account_binding(
                AcmeEndpointArn=endpoint_arn,
                RoleArn=role_arn,
                Expiration={"Type": "DAYS", "Value": 7},
                Tags=[{"Key": "Purpose", "Value": "sim2real-behavioral"}],
            )["ExternalAccountBinding"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
