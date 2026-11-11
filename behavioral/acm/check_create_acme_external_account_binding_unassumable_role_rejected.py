"""create-acme-external-account-binding-unassumable-role-rejected."""
from __future__ import annotations

import json
import time
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-acme-external-account-binding-unassumable-role-rejected"
GROUP = "overly-permissive"
SERVICES = ["acm"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateAcmeExternalAccountBinding with a role the ACME service principal cannot assume is
    refused with AccessDeniedException and creates no binding, while a role trusting
    acm-acme.amazonaws.com is accepted and its binding can be deleted without revoking first."""
    acm = ctx.client("acm")
    endpoint_arn = _create_active_endpoint(ctx)

    bad_role_arn = _create_eab_role(ctx, allow_acme=False)
    good_role_arn = _create_eab_role(ctx, allow_acme=True)

    # The trusted role goes first: its bounded retry outlasts IAM propagation of both fresh
    # roles, so the refusal below is ACM's trust evaluation, not a not-yet-visible role.
    eab = _create_binding_with_retry(ctx, endpoint_arn, good_role_arn)["ExternalAccountBinding"]
    eab_arn = eab["AcmeExternalAccountBindingArn"]
    ctx.on_cleanup(lambda: _ignore(lambda: acm.delete_acme_external_account_binding(AcmeExternalAccountBindingArn=eab_arn)))
    assert eab["RoleArn"] == good_role_arn, f"expected RoleArn {good_role_arn!r}, got {eab['RoleArn']!r}"
    assert eab.get("RevokedAt") is None, f"a freshly created binding must not be revoked, got RevokedAt={eab.get('RevokedAt')!r}"

    expected_message = (
        f"Unable to assume role for {bad_role_arn}. Verify that the role exists and its trust policy "
        "grants acm-acme.amazonaws.com access to sts:AssumeRole, sts:SetSourceIdentity, and sts:TagSession."
    )
    code, message = _settled_refusal(
        lambda: acm.create_acme_external_account_binding(AcmeEndpointArn=endpoint_arn, RoleArn=bad_role_arn),
        expected_message,
    )
    assert code == "AccessDeniedException", f"expected AccessDeniedException for an unassumable RoleArn, got {code} ({message!r})"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    listing = acm.list_acme_external_account_bindings(AcmeEndpointArn=endpoint_arn)["ExternalAccountBindings"]
    listed = [b["AcmeExternalAccountBindingArn"] for b in listing]
    assert listed == [eab_arn], f"only the trusted role's binding may exist, found {listing}"

    # Deleting and revoking an EAB are independent; a non-revoked binding deletes directly.
    acm.delete_acme_external_account_binding(AcmeExternalAccountBindingArn=eab_arn)
    code_after_delete, message_after_delete = _error_code(
        lambda: acm.describe_acme_external_account_binding(AcmeExternalAccountBindingArn=eab_arn)
    )
    assert code_after_delete == "ResourceNotFoundException", f"expected binding gone after delete, got {code_after_delete}"
    expected_message = f"Could not find ACME external account binding {eab_arn}."
    assert message_after_delete == expected_message, (
        f"expected message {expected_message!r}, got {message_after_delete!r}"
    )


def _error_code(fn: Callable[[], Any]) -> tuple[str, str | None]:
    """The captured AWS error (code, message); an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _settled_refusal(fn: Callable[[], Any], expected_message: str, *, timeout_s: float = 60.0, interval_s: float = 3.0) -> tuple[str, str | None]:
    """The refusal fn() settles to once IAM has propagated the role: an AccessDeniedException with
    any other message (iam:PassRole on a not-yet-propagated role) is retried until the deadline."""
    deadline = time.monotonic() + timeout_s
    while True:
        code, message = _error_code(fn)
        if code != "AccessDeniedException" or message == expected_message or time.monotonic() >= deadline:
            return code, message
        time.sleep(interval_s)


def _create_binding_with_retry(ctx, endpoint_arn: str, role_arn: str, *, timeout_s: float = 60.0, interval_s: float = 3.0) -> dict[str, Any]:
    """Retry CreateAcmeExternalAccountBinding through IAM propagation: an AccessDeniedException
    there means ACM has not yet seen the role's trust policy, not that it was evaluated."""
    acm = ctx.client("acm")
    deadline = time.monotonic() + timeout_s
    last_err: ClientError | None = None
    while time.monotonic() < deadline:
        try:
            return acm.create_acme_external_account_binding(AcmeEndpointArn=endpoint_arn, RoleArn=role_arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException":
                raise
            last_err = exc
            time.sleep(interval_s)
    raise AssertionError(f"CreateAcmeExternalAccountBinding never converged for a correctly-trusted role: {last_err}")


def _ignore(fn: Callable[[], Any]) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _poll_until(probe: Callable[[], Any], predicate: Callable[[Any], bool], *, timeout_s: float = 60.0, interval_s: float = 2.0) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    return last


def _create_active_endpoint(ctx, contact: str = "NOT_REQUIRED") -> str:
    acm = ctx.client("acm")
    resp = acm.create_acme_endpoint(
        AuthorizationBehavior="PRE_APPROVED",
        CertificateAuthority={"PublicCertificateAuthority": {"AllowedKeyAlgorithms": ["EC_prime256v1"]}},
        Contact=contact,
        Tags=[{"Key": "Name", "Value": ctx.unique_name("sim2real-acme-ep-")}],
    )
    arn = resp["AcmeEndpointArn"]
    ctx.on_cleanup(lambda: _ignore(lambda: acm.delete_acme_endpoint(AcmeEndpointArn=arn)))
    status = _poll_until(
        lambda: acm.describe_acme_endpoint(AcmeEndpointArn=arn)["AcmeEndpoint"]["Status"],
        lambda s: s in ("ACTIVE", "FAILED"),
        timeout_s=120,
        interval_s=3,
    )
    assert status == "ACTIVE", f"ACME endpoint did not become ACTIVE (status={status})"
    return arn


def _create_eab_role(ctx, allow_acme: bool) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-acme-eab-role-")
    if allow_acme:
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
    else:
        trust_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}
            ],
        }
    resp = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust_policy))
    role_arn = resp["Role"]["Arn"]
    ctx.on_cleanup(lambda: _ignore(lambda: iam.delete_role(RoleName=name)))
    return role_arn


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
