"""acme-external-account-binding-lifecycle."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "acme-external-account-binding-lifecycle"
GROUP = "state-machine"
SERVICES = ["acm"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateAcmeExternalAccountBinding is describable, RevokeAcmeExternalAccountBinding
    transitions it to a revoked (RevokedAt set) state, and DeleteAcmeExternalAccountBinding
    finally removes it (describe 404)."""
    acm = ctx.client("acm")
    endpoint_arn = _create_acme_endpoint(ctx)
    role_arn = _create_eab_role(ctx)

    create_resp = _create_binding_with_retry(ctx, endpoint_arn, role_arn)
    binding_arn = create_resp["ExternalAccountBinding"]["AcmeExternalAccountBindingArn"]
    ctx.on_cleanup(lambda: _delete_binding_ignore_errors(ctx, binding_arn))

    described = acm.describe_acme_external_account_binding(
        AcmeExternalAccountBindingArn=binding_arn
    )["ExternalAccountBinding"]
    assert described["AcmeExternalAccountBindingArn"] == binding_arn, (
        f"describe returned a different binding ARN: expected {binding_arn}, "
        f"got {described['AcmeExternalAccountBindingArn']}"
    )
    assert described["AcmeEndpointArn"] == endpoint_arn, (
        f"expected AcmeEndpointArn {endpoint_arn}, got {described['AcmeEndpointArn']}"
    )
    assert described["RoleArn"] == role_arn, f"expected RoleArn {role_arn}, got {described['RoleArn']}"
    assert described.get("RevokedAt") is None, (
        f"freshly created binding must not be revoked yet, got RevokedAt={described.get('RevokedAt')!r}"
    )

    acm.revoke_acme_external_account_binding(AcmeExternalAccountBindingArn=binding_arn)

    def _probe():
        return acm.describe_acme_external_account_binding(
            AcmeExternalAccountBindingArn=binding_arn
        )["ExternalAccountBinding"]

    revoked = _poll_until(_probe, lambda d: d.get("RevokedAt") is not None, timeout_s=60.0, interval_s=3.0)
    assert revoked["RevokedAt"] is not None, "RevokedAt still unset after RevokeAcmeExternalAccountBinding"

    acm.delete_acme_external_account_binding(AcmeExternalAccountBindingArn=binding_arn)
    _wait_for_binding_gone(ctx, binding_arn)


def _poll_until(probe, predicate, *, timeout_s: float = 60.0, interval_s: float = 2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _create_acme_endpoint(ctx, contact: str = "NOT_REQUIRED") -> str:
    acm = ctx.client("acm")
    name = ctx.unique_name("sim2real-acme-eab-ep-")
    resp = acm.create_acme_endpoint(
        AuthorizationBehavior="PRE_APPROVED",
        CertificateAuthority={"PublicCertificateAuthority": {}},
        Contact=contact,
        Tags=[{"Key": "Name", "Value": name}],
    )
    arn = resp["AcmeEndpointArn"]
    ctx.on_cleanup(lambda: _delete_endpoint_ignore_errors(ctx, arn))
    status = _wait_for_endpoint_terminal(ctx, arn)
    if status != "ACTIVE":
        raise AssertionError(f"AcmeEndpoint {arn} settled in status {status}, expected ACTIVE")
    return arn


def _wait_for_endpoint_terminal(ctx, arn: str, timeout_s: float = 120.0, interval_s: float = 3.0) -> str:
    acm = ctx.client("acm")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = acm.describe_acme_endpoint(AcmeEndpointArn=arn)["AcmeEndpoint"]["Status"]
        if last in ("ACTIVE", "FAILED"):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"AcmeEndpoint {arn} never left a non-terminal status; last={last}")


def _delete_endpoint_ignore_errors(ctx, arn: str) -> None:
    from botocore.exceptions import ClientError

    acm = ctx.client("acm")
    acm.delete_acme_endpoint(AcmeEndpointArn=arn)


def _create_eab_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-acme-eab-role-")
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
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "Name", "Value": role_name}],
    )
    ctx.on_cleanup(lambda: _delete_role_ignore_errors(ctx, role_name))
    return resp["Role"]["Arn"]


def _delete_role_ignore_errors(ctx, role_name: str) -> None:
    from botocore.exceptions import ClientError

    iam = ctx.client("iam")
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _create_binding_with_retry(ctx, endpoint_arn: str, role_arn: str, timeout_s: float = 60.0):
    from botocore.exceptions import ClientError

    acm = ctx.client("acm")
    tag_name = ctx.unique_name("sim2real-acme-eab-")
    deadline = time.monotonic() + timeout_s
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            return acm.create_acme_external_account_binding(
                AcmeEndpointArn=endpoint_arn,
                RoleArn=role_arn,
                Tags=[{"Key": "Name", "Value": tag_name}],
            )
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in ("AccessDeniedException", "ValidationException"):
                # IAM role trust-policy propagation lag.
                last_err = e
                time.sleep(3.0)
                continue
            raise
    raise AssertionError(f"CreateAcmeExternalAccountBinding never succeeded: {last_err}")


def _wait_for_binding_gone(ctx, binding_arn: str, timeout_s: float = 90.0, interval_s: float = 3.0) -> None:
    from botocore.exceptions import ClientError

    acm = ctx.client("acm")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            acm.describe_acme_external_account_binding(AcmeExternalAccountBindingArn=binding_arn)
        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(interval_s)
    raise AssertionError(f"binding {binding_arn} still describable after {timeout_s}s")


def _delete_binding_ignore_errors(ctx, binding_arn: str) -> None:
    from botocore.exceptions import ClientError

    acm = ctx.client("acm")
    acm.delete_acme_external_account_binding(AcmeExternalAccountBindingArn=binding_arn)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
