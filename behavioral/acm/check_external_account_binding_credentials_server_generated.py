"""external-account-binding-credentials-server-generated."""
from __future__ import annotations

import json
import re
import time
from typing import Any

from behavioral_harness import tags

CHECK = "external-account-binding-credentials-server-generated"
GROUP = "server-side"
SERVICES = ["acm"]

_EAB_CREDS_ARN_RE = re.compile(
    r"^arn:aws[a-z-]*:acm:[a-z0-9-]+:[0-9]{12}:acme-endpoint/[a-zA-Z0-9-]+"
    r"/acme-external-account-binding/[a-zA-Z0-9-]+$"
)


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetAcmeExternalAccountBindingCredentials returns a server-generated KeyId/MacKey pair that
    echoes no caller-supplied identifier and is stable across reads; fetching it leaves the
    binding's LastUsedAt unset, since only an ACME account registration uses the credentials."""
    acm = ctx.client("acm")

    role_arn = _create_eab_role(ctx)
    endpoint_arn = _create_acme_endpoint(ctx)
    endpoint = _wait_for_endpoint_active(ctx, endpoint_arn)
    assert endpoint["Status"] == "ACTIVE", f"expected ACTIVE, got {endpoint['Status']}"

    eab = _create_eab(ctx, endpoint_arn, role_arn)
    eab_arn = eab["AcmeExternalAccountBindingArn"]
    assert _EAB_CREDS_ARN_RE.match(eab_arn), f"unexpected EAB arn shape: {eab_arn}"
    assert eab["RoleArn"] == role_arn, f"expected RoleArn={role_arn}, got {eab['RoleArn']}"
    assert eab["AcmeEndpointArn"] == endpoint_arn, (
        f"expected AcmeEndpointArn={endpoint_arn}, got {eab['AcmeEndpointArn']}"
    )

    # Before any credential retrieval, LastUsedAt must not be set yet.
    pre = acm.describe_acme_external_account_binding(AcmeExternalAccountBindingArn=eab_arn)[
        "ExternalAccountBinding"
    ]
    assert "LastUsedAt" not in pre or pre["LastUsedAt"] is None, (
        f"expected no LastUsedAt before any credential fetch, got {pre.get('LastUsedAt')!r}"
    )

    creds1 = acm.get_acme_external_account_binding_credentials(
        AcmeExternalAccountBindingArn=eab_arn
    )
    key_id_1, mac_key_1 = creds1["KeyId"], creds1["MacKey"]

    # The server-generated credentials must not echo any client-supplied identifier from
    # creation time, and must be substantial (not trivially short) secrets.
    supplied_inputs = {role_arn, endpoint_arn, eab_arn}
    assert key_id_1 not in supplied_inputs, f"KeyId echoed a caller-supplied identifier: {key_id_1}"
    assert mac_key_1 not in supplied_inputs, f"MacKey echoed a caller-supplied identifier: {mac_key_1}"
    assert key_id_1 != mac_key_1, "KeyId and MacKey must not be equal"
    assert len(key_id_1) >= 8, f"KeyId too short to be a real secret: {len(key_id_1)} chars"
    assert len(mac_key_1) >= 16, f"MacKey too short to be a real secret: {len(mac_key_1)} chars"

    # A second read returns the SAME credentials -- they are a stored server-side artifact
    # bound to the EAB, not freshly (re)computed/regenerated on every call.
    creds2 = acm.get_acme_external_account_binding_credentials(
        AcmeExternalAccountBindingArn=eab_arn
    )
    assert creds2["KeyId"] == key_id_1, (
        f"KeyId changed across repeated fetches: {key_id_1!r} -> {creds2['KeyId']!r}"
    )
    assert creds2["MacKey"] == mac_key_1, (
        f"MacKey changed across repeated fetches: {mac_key_1!r} -> {creds2['MacKey']!r}"
    )

    # Reading the credentials is not their use: only an ACME account registration sets LastUsedAt.
    post = acm.describe_acme_external_account_binding(AcmeExternalAccountBindingArn=eab_arn)[
        "ExternalAccountBinding"
    ]
    assert "LastUsedAt" not in post or post["LastUsedAt"] is None, (
        f"expected no LastUsedAt after repeated credential fetches, got {post.get('LastUsedAt')!r}"
    )
    assert post["AcmeExternalAccountBindingArn"] == eab_arn, (
        f"expected AcmeExternalAccountBindingArn={eab_arn}, got {post['AcmeExternalAccountBindingArn']}"
    )
    assert post["RoleArn"] == role_arn, f"expected RoleArn={role_arn}, got {post['RoleArn']}"


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _error_code(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
        return None
    except ClientError as err:
        return err.response["Error"]["Code"]


def _create_eab_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-acm-eab-role-")[:64]
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "acm-acme.amazonaws.com"},
                "Action": ["sts:AssumeRole", "sts:TagSession", "sts:SetSourceIdentity"],
                "Condition": {
                    "StringLikeIfExists": {"sts:SourceIdentity": "acm-acme-*"}
                },
            }
        ],
    }
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "Name", "Value": role_name}],
    )
    role_arn = resp["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return role_arn


def _create_acme_endpoint(ctx, **overrides: Any) -> str:
    acm = ctx.client("acm")
    params: dict[str, Any] = {
        "AuthorizationBehavior": "PRE_APPROVED",
        "CertificateAuthority": {"PublicCertificateAuthority": {}},
        "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-acm-endpoint-")}],
    }
    params.update(overrides)
    arn = acm.create_acme_endpoint(**params)["AcmeEndpointArn"]
    ctx.on_cleanup(lambda: acm.delete_acme_endpoint(AcmeEndpointArn=arn))
    return arn


def _wait_for_endpoint_active(ctx, endpoint_arn, timeout_s=180.0, interval_s=5.0):
    acm = ctx.client("acm")

    def probe():
        return acm.describe_acme_endpoint(AcmeEndpointArn=endpoint_arn)["AcmeEndpoint"]

    def done(desc):
        if desc["Status"] == "FAILED":
            raise AssertionError(f"AcmeEndpoint {endpoint_arn} FAILED: {desc.get('FailureReason')}")
        return desc["Status"] == "ACTIVE"

    return _poll_until(probe, done, timeout_s=timeout_s, interval_s=interval_s)


def _create_eab(ctx, endpoint_arn, role_arn):
    acm = ctx.client("acm")

    def attempt():
        return acm.create_acme_external_account_binding(
            AcmeEndpointArn=endpoint_arn, RoleArn=role_arn
        )["ExternalAccountBinding"]

    # A freshly created IAM role can briefly be invisible to other services (IAM eventual
    # consistency), so retry AccessDenied for a bounded window before treating it as real.
    deadline = time.monotonic() + 30.0
    last_err = None
    while time.monotonic() < deadline:
        try:
            eab = attempt()
            eab_arn = eab["AcmeExternalAccountBindingArn"]
            ctx.on_cleanup(
                lambda arn=eab_arn: acm.delete_acme_external_account_binding(
                    AcmeExternalAccountBindingArn=arn
                )
            )
            return eab
        except Exception as err:  # noqa: BLE001
            code = getattr(err, "response", {}).get("Error", {}).get("Code")
            if code != "AccessDeniedException":
                raise
            last_err = err
            time.sleep(3)
    raise AssertionError(f"CreateAcmeExternalAccountBinding never succeeded: {last_err}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
