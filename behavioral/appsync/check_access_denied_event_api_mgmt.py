"""access-denied-event-api-mgmt."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

_PROPAGATION = frozenset({"InvalidClientTokenId", "UnrecognizedClientException"})

def _error(fn, *, retry_propagation=False, timeout_s=60, interval_s=3):
    """Call fn(); return the (code, message) of its ClientError. An unexpected success raises.
    When retry_propagation is set, a freshly minted access key's transient
    InvalidClientTokenId/UnrecognizedClientException is retried on a bounded deadline rather than
    trusted as the verdict."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            result = fn()
        except ClientError as exc:
            err = exc.response.get("Error", {})
            code = err.get("Code")
            if retry_propagation and code in _PROPAGATION and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            return code, err.get("Message")
        raise AssertionError(f"expected a rejection, but the call succeeded and returned {result!r}")

def _implicit_deny(principal_arn, action, resource):
    """AWS's AccessDeniedException message for a principal with no policy granting ``action``."""
    return (
        f"User: {principal_arn} is not authorized to perform: appsync:{action} on resource: "
        f"{resource} because no identity-based policy allows the appsync:{action} action"
    )

def _denied_client(ctx):
    """Provision a throwaway IAM user with ZERO attached policies (implicit deny on every action)
    and return its ARN plus a fresh appsync client credentialed as that user. Credential
    propagation lag is absorbed per-call by ``_error(..., retry_propagation=True)``."""
    iam = ctx.client("iam")
    user = ctx.unique_name("sim2real-behav-denied-")
    user_arn = iam.create_user(UserName=user, Tags=[{"Key": "sim2real", "Value": CHECK}])["User"]["Arn"]
    def _cleanup_user(_u=user, _iam=iam):
        for k in _iam.list_access_keys(UserName=_u).get("AccessKeyMetadata", []):
            _iam.delete_access_key(UserName=_u, AccessKeyId=k["AccessKeyId"])
        _iam.delete_user(UserName=_u)
    ctx.on_cleanup(_cleanup_user)
    key = iam.create_access_key(UserName=user)["AccessKey"]
    client = ctx.client("appsync", creds={
        "aws_access_key_id": key["AccessKeyId"],
        "aws_secret_access_key": key["SecretAccessKey"],
    })
    code, message = _error(lambda: client.list_apis(), retry_propagation=True)
    assert code == "AccessDeniedException", (
        f"ListApis: expected AccessDeniedException for an unauthorized principal, got {code}"
    )
    account_id = user_arn.split(":")[4]
    expected = _implicit_deny(user_arn, "ListApis", f"arn:aws:appsync:{ctx.region}:{account_id}:*")
    assert message == expected, f"ListApis: expected message {expected!r}, got {message!r}"
    return user_arn, client

CHECK = "access-denied-event-api-mgmt"
GROUP = 'overly-permissive'
SERVICES = ['appsync']

def _tolerate_notfound(fn, **kwargs):
    """Run a teardown call, tolerating the target already being gone."""
    try:
        fn(**kwargs)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NotFoundException":
            raise

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Event API management calls from a zero-policy principal fail with AccessDeniedException.

    Permissioned credentials get NotFoundException on the domain calls and can update/delete a
    sibling API, so each denial is an authorization gate, not a blanket 403.
    """
    svc = ctx.client("appsync")
    api = svc.create_api(name=ctx.unique_name("sim2real-behav-appsync-eventapi-"), eventConfig={"authProviders": [{"authType": "API_KEY"}, {"authType": "AWS_IAM"}], "connectionAuthModes": [{"authType": "API_KEY"}], "defaultPublishAuthModes": [{"authType": "API_KEY"}], "defaultSubscribeAuthModes": [{"authType": "API_KEY"}]}, tags={"sim2real": CHECK, "sim2real:managed": "true"})["api"]
    ctx.on_cleanup(lambda _a=api: svc.delete_api(apiId=_a["apiId"]))
    api_id = api["apiId"]
    domain = f"{ctx.unique_name('sim2real-behav-dn-')}.com"  # syntactically valid, never created

    user_arn, denied = _denied_client(ctx)
    account_id = user_arn.split(":")[4]
    domain_arn = f"arn:aws:appsync:{ctx.region}:{account_id}:domainnames/{domain}"
    api_arn = api["apiArn"]

    checks = [
        ("GetApi", api_arn, lambda: denied.get_api(apiId=api_id)),
        ("UpdateApi", api_arn,
         lambda: denied.update_api(apiId=api_id, name=api["name"], eventConfig=api["eventConfig"])),
        ("DeleteApi", api_arn, lambda: denied.delete_api(apiId=api_id)),
        ("AssociateApi", domain_arn, lambda: denied.associate_api(domainName=domain, apiId=api_id)),
        ("GetApiAssociation", domain_arn, lambda: denied.get_api_association(domainName=domain)),
        ("DisassociateApi", domain_arn, lambda: denied.disassociate_api(domainName=domain)),
    ]
    for label, resource, fn in checks:
        code, message = _error(fn, retry_propagation=True)
        assert code == "AccessDeniedException", (
            f"{label}: expected AccessDeniedException for an unauthorized principal, got {code}"
        )
        expected = _implicit_deny(user_arn, label, resource)
        assert message == expected, f"{label}: expected message {expected!r}, got {message!r}"

    # Positive control: the same domain-scoped calls with permissioned credentials reach lookup.
    domain_checks = [
        ("AssociateApi", "Domain name not found.",
         lambda: svc.associate_api(domainName=domain, apiId=api_id)),
        ("GetApiAssociation", "Domain name not found",
         lambda: svc.get_api_association(domainName=domain)),
        ("DisassociateApi", "Domain name not found.",
         lambda: svc.disassociate_api(domainName=domain)),
    ]
    for label, expected_message, fn in domain_checks:
        code, message = _error(fn)
        assert code == "NotFoundException", (
            f"{label} (positive control, permissioned creds): expected NotFoundException for a "
            f"domain that was never created, got {code}"
        )
        assert message == expected_message, (
            f"{label}: expected message {expected_message!r}, got {message!r}"
        )

    # Positive control for UpdateApi/DeleteApi on a throwaway sibling API.
    control_api = svc.create_api(
        name=ctx.unique_name("sim2real-behav-appsync-control-"), eventConfig=api["eventConfig"],
        tags={"sim2real": CHECK, "sim2real:managed": "true"},
    )["api"]
    control_id = control_api["apiId"]
    ctx.on_cleanup(lambda _c=control_id: _tolerate_notfound(svc.delete_api, apiId=_c))
    svc.update_api(apiId=control_id, name=control_api["name"], eventConfig=control_api["eventConfig"])
    svc.delete_api(apiId=control_id)
    control_gone_code, control_gone_message = _error(lambda: svc.get_api(apiId=control_id))
    assert control_gone_code == "NotFoundException", (
        "control API delete: expected the authorized-principal delete to have taken effect "
        f"(NotFoundException on GetApi), got {control_gone_code}"
    )
    assert control_gone_message == "API not found.", control_gone_message

    # The denied attempts left the API untouched; this is also GetApi's positive control.
    still_there = svc.get_api(apiId=api_id)["api"]
    assert still_there["apiId"] == api_id, (
        f"expected the untouched API {api_id!r} still present, got {still_there.get('apiId')!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
