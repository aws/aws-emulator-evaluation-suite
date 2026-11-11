"""get-eab-credentials-after-revoke-not-found."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-eab-credentials-after-revoke-not-found"
GROUP = "error-semantics"
SERVICES = ["acm"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """After RevokeAcmeExternalAccountBinding, GetAcmeExternalAccountBindingCredentials is refused
    with ValidationException and the exact "has been revoked" message, while the binding stays
    describable with RevokedAt set and its ARN and role unchanged."""
    acm = ctx.client("acm")
    endpoint_arn = _create_acme_endpoint(ctx)
    _wait_for_endpoint_status(ctx, endpoint_arn, {"ACTIVE"})
    role_arn = _create_eab_role(ctx)
    binding_arn = _create_eab_binding(ctx, endpoint_arn, role_arn)

    # positive control: credentials are retrievable before revocation
    creds = acm.get_acme_external_account_binding_credentials(AcmeExternalAccountBindingArn=binding_arn)
    assert creds.get("KeyId"), "expected a KeyId in the pre-revoke credentials response"
    assert creds.get("MacKey"), "expected a MacKey in the pre-revoke credentials response"

    acm.revoke_acme_external_account_binding(AcmeExternalAccountBindingArn=binding_arn)

    def _probe():
        return _error(
            lambda: acm.get_acme_external_account_binding_credentials(AcmeExternalAccountBindingArn=binding_arn)
        )

    code, message = _poll_until_code(_probe, "ValidationException", timeout_s=60.0)
    assert code == "ValidationException", f"expected ValidationException after revoke, got {code!r}"
    assert message == f"The ACME external account binding {binding_arn} has been revoked.", message

    # the binding record itself still exists (it was revoked, not deleted) -- only the
    # credentials became unavailable, confirming this is not a generic cascading delete
    def _describe():
        return acm.describe_acme_external_account_binding(AcmeExternalAccountBindingArn=binding_arn)[
            "ExternalAccountBinding"
        ]

    described = _poll_until(_describe, lambda b: b.get("RevokedAt") is not None, timeout_s=30.0)
    assert described.get("RevokedAt") is not None, "expected RevokedAt to be set on the binding after revoke"
    assert described["AcmeExternalAccountBindingArn"] == binding_arn, (
        f"binding ARN changed after revoke -- expected the same record, got {described.get('AcmeExternalAccountBindingArn')!r}"
    )
    assert described["RoleArn"] == role_arn, (
        f"RoleArn changed after revoke -- expected the record preserved, not recreated, got {described.get('RoleArn')!r}"
    )


def _error(fn):
    """The (code, message) of the ClientError fn raises, or ("SUCCEEDED", None) when it succeeds."""
    try:
        fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    return "SUCCEEDED", None


def _poll_until_code(probe, expected_code, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if last[0] == expected_code:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"expected code {expected_code!r} within {timeout_s}s, last observed {last!r}")


def _poll_until(probe, predicate, timeout_s=30.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last observed {last!r}")


def _create_acme_endpoint(ctx):
    acm = ctx.client("acm")
    resp = acm.create_acme_endpoint(
        AuthorizationBehavior="PRE_APPROVED",
        CertificateAuthority={"PublicCertificateAuthority": {}},
        Tags=[{"Key": "Name", "Value": ctx.unique_name("sim2real-acm-endpoint-")}],
    )
    arn = resp["AcmeEndpointArn"]
    ctx.on_cleanup(lambda: _delete_acme_endpoint(ctx, arn))
    return arn


def _delete_acme_endpoint(ctx, arn):
    acm = ctx.client("acm")
    acm.delete_acme_endpoint(AcmeEndpointArn=arn)


def _wait_for_endpoint_status(ctx, arn, target_statuses, timeout_s=90.0, interval_s=3.0):
    acm = ctx.client("acm")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = acm.describe_acme_endpoint(AcmeEndpointArn=arn)["AcmeEndpoint"]["Status"]
        if last in target_statuses:
            return last
        if last == "FAILED" and "FAILED" not in target_statuses:
            raise AssertionError(f"endpoint {arn} settled in FAILED while waiting for {target_statuses}")
        time.sleep(interval_s)
    raise AssertionError(f"endpoint {arn} never reached {target_statuses}, last status {last!r}")


def _create_eab_role(ctx):
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-acme-eab-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "acm-acme.amazonaws.com"},
                "Action": ["sts:AssumeRole", "sts:SetSourceIdentity", "sts:TagSession"],
            }
        ],
    }
    resp = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "Name", "Value": name}],
    )
    arn = resp["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(ctx, name))
    return arn


def _delete_role(ctx, name):
    iam = ctx.client("iam")
    try:
        iam.delete_role(RoleName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _create_eab_binding(ctx, endpoint_arn, role_arn, timeout_s=90.0, interval_s=5.0):
    acm = ctx.client("acm")
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            resp = acm.create_acme_external_account_binding(
                AcmeEndpointArn=endpoint_arn,
                RoleArn=role_arn,
                Tags=[{"Key": "Name", "Value": ctx.unique_name("sim2real-acm-eab-")}],
            )
            binding_arn = resp["ExternalAccountBinding"]["AcmeExternalAccountBindingArn"]
            ctx.on_cleanup(lambda arn=binding_arn: _delete_binding(ctx, arn))
            return binding_arn
        except ClientError as err:
            last_err = err
            # tolerate IAM role propagation lag right after create_role
            if err.response["Error"]["Code"] not in ("AccessDeniedException", "ValidationException"):
                raise
            time.sleep(interval_s)
    raise AssertionError(f"could not create external account binding within {timeout_s}s: {last_err}")


def _delete_binding(ctx, arn):
    acm = ctx.client("acm")
    acm.delete_acme_external_account_binding(AcmeExternalAccountBindingArn=arn)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
