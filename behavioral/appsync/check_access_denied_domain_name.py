"""access-denied-domain-name."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

def _error(fn):
    """Call fn(); return the (code, message) of its ClientError. An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call succeeded and returned {result!r}")

def _implicit_deny(principal_arn, action, resource):
    """AWS's AccessDeniedException message for a principal with no policy granting ``action``."""
    return (
        f"User: {principal_arn} is not authorized to perform: appsync:{action} on resource: "
        f"{resource} because no identity-based policy allows the appsync:{action} action"
    )

def _poll_until_denied(fn, *, timeout_s=60.0, interval_s=3.0, description="condition"):
    """Bounded retry for IAM credential propagation: a freshly-created access key can be rejected
    with an authentication error (not yet recognized) before it settles into the expected
    AccessDeniedException. Returns (code, message); raises on timeout."""
    deadline = time.monotonic() + timeout_s
    code = None
    while time.monotonic() < deadline:
        code, message = _error(fn)
        if code == "AccessDeniedException":
            return code, message
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s; last code={code!r}")

def _denied_client(ctx):
    """Provision a throwaway IAM user with ZERO attached policies (implicit deny on every action)
    and return its ARN plus a fresh appsync client credentialed as that user."""
    iam = ctx.client("iam")
    user = ctx.unique_name("sim2real-behav-denied-")
    user_arn = iam.create_user(UserName=user, Tags=[{"Key": "sim2real", "Value": CHECK}])["User"]["Arn"]
    def _cleanup_user(_u=user, _iam=iam):
        for k in _iam.list_access_keys(UserName=_u).get("AccessKeyMetadata", []):
            _iam.delete_access_key(UserName=_u, AccessKeyId=k["AccessKeyId"])
        _iam.delete_user(UserName=_u)
    ctx.on_cleanup(_cleanup_user)
    key = iam.create_access_key(UserName=user)["AccessKey"]
    return user_arn, ctx.client("appsync", creds={
        "aws_access_key_id": key["AccessKeyId"],
        "aws_secret_access_key": key["SecretAccessKey"],
    })

CHECK = "access-denied-domain-name"
GROUP = 'overly-permissive'
SERVICES = ['appsync']

@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Domain-name CRUD/List from a zero-policy principal fail AccessDeniedException before lookup.

    The caller's own credentials get NotFoundException/BadRequestException, so the denial is IAM's.
    """
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    domain = f"{ctx.unique_name('sim2real-behav-dn-')}.com"
    cert_arn = (
        f"arn:aws:acm:{ctx.region}:{account_id}:certificate/00000000-0000-0000-0000-000000000000"
    )
    user_arn, denied = _denied_client(ctx)
    domain_arn = f"arn:aws:appsync:{ctx.region}:{account_id}:domainnames/{domain}"
    account_scope = f"arn:aws:appsync:{ctx.region}:{account_id}:*"

    checks = [
        ("CreateDomainName", domain_arn, lambda: denied.create_domain_name(
            domainName=domain, certificateArn=cert_arn,
        )),
        ("GetDomainName", domain_arn, lambda: denied.get_domain_name(domainName=domain)),
        ("UpdateDomainName", domain_arn,
         lambda: denied.update_domain_name(domainName=domain, description="x")),
        ("DeleteDomainName", domain_arn, lambda: denied.delete_domain_name(domainName=domain)),
        ("ListDomainNames", account_scope, lambda: denied.list_domain_names()),
    ]
    for label, resource, fn in checks:
        code, message = _poll_until_denied(
            fn, description=f"{label} denied for the unauthorized principal"
        )
        assert code == "AccessDeniedException", (
            f"{label}: expected AccessDeniedException for an unauthorized principal, got {code}"
        )
        expected = _implicit_deny(user_arn, label, resource)
        assert message == expected, f"{label}: expected message {expected!r}, got {message!r}"

    # Positive control: unrestricted credentials reach resource lookup on the same domain.
    admin = ctx.client("appsync")
    for label, expected_message, fn in [
        ("GetDomainName", "Domain name not found",
         lambda: admin.get_domain_name(domainName=domain)),
        ("UpdateDomainName", "Domain name not found",
         lambda: admin.update_domain_name(domainName=domain, description="x")),
        ("DeleteDomainName", "Domain name not found.",
         lambda: admin.delete_domain_name(domainName=domain)),
    ]:
        admin_code, admin_message = _error(fn)
        assert admin_code == "NotFoundException", (
            f"{label}: expected the unrestricted principal to fail on resource lookup "
            f"(NotFoundException) for a domain that was never created, got {admin_code}"
        )
        assert admin_message == expected_message, (
            f"{label}: expected message {expected_message!r}, got {admin_message!r}"
        )
    admin.list_domain_names()

    # The unrestricted principal's CreateDomainName gets past IAM and is refused by the service on
    # the placeholder certificate, which sits in the caller's region rather than us-east-1.
    admin_create_code, admin_create_message = _error(lambda: admin.create_domain_name(
        domainName=domain, certificateArn=cert_arn,
    ))
    assert admin_create_code == "BadRequestException", (
        f"CreateDomainName: the unrestricted principal must reach certificate validation, "
        f"got {admin_create_code}"
    )
    assert admin_create_message == "Certificate must be in us-east-1.", admin_create_message

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
