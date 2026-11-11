"""eab-hmac-key-base64-round-trip."""
from __future__ import annotations

import base64
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "eab-hmac-key-base64-round-trip"
GROUP = "representation"
SERVICES = ["acm"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """The base64-encoded MAC key returned by GetAcmeExternalAccountBindingCredentials is
    byte-identical across repeated fetches of the same binding, and decodes cleanly as base64
    (the ACME hmacKey used in account registration).
    """
    acm = ctx.client("acm")
    endpoint_arn, _ = _create_active_acme_endpoint(ctx, acm)
    role_arn = _create_eab_role(ctx)
    binding = _create_binding_with_retry(ctx, acm, endpoint_arn, role_arn)
    binding_arn = binding["AcmeExternalAccountBindingArn"]
    ctx.on_cleanup(lambda: acm.delete_acme_external_account_binding(AcmeExternalAccountBindingArn=binding_arn))

    mac_keys = []
    key_ids = []
    for _ in range(2):
        creds = acm.get_acme_external_account_binding_credentials(AcmeExternalAccountBindingArn=binding_arn)
        mac_keys.append(creds["MacKey"])
        key_ids.append(creds["KeyId"])
        time.sleep(1)

    assert mac_keys[0] == mac_keys[1], "MacKey differed between repeated fetches of the same binding"
    assert key_ids[0] == key_ids[1], "KeyId differed between repeated fetches of the same binding"
    assert _base64_decodable(mac_keys[0]), f"MacKey is not valid base64: {mac_keys[0]!r}"
    assert len(base64.urlsafe_b64decode(_pad(mac_keys[0]))) >= 16, "decoded MacKey is implausibly short for an HMAC key"


_EAB_TRUST_POLICY = json.dumps(
    {
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
)


def _create_active_acme_endpoint(ctx, acm, timeout_s: float = 180.0, interval_s: float = 5.0):
    resp = acm.create_acme_endpoint(
        AuthorizationBehavior="PRE_APPROVED",
        Contact="NOT_REQUIRED",
        CertificateAuthority={"PublicCertificateAuthority": {}},
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    arn = resp["AcmeEndpointArn"]
    ctx.on_cleanup(lambda: acm.delete_acme_endpoint(AcmeEndpointArn=arn))

    deadline = time.monotonic() + timeout_s
    endpoint = acm.describe_acme_endpoint(AcmeEndpointArn=arn)["AcmeEndpoint"]
    while endpoint["Status"] == "CREATING" and time.monotonic() < deadline:
        time.sleep(interval_s)
        endpoint = acm.describe_acme_endpoint(AcmeEndpointArn=arn)["AcmeEndpoint"]
    if endpoint["Status"] != "ACTIVE":
        raise AssertionError(
            f"ACME endpoint never reached ACTIVE (status={endpoint['Status']}, "
            f"reason={endpoint.get('FailureReason')})"
        )
    return arn, endpoint["EndpointUrl"]


def _create_eab_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-acme-eab-role-")
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=_EAB_TRUST_POLICY,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    role_arn = resp["Role"]["Arn"]
    policy_name = "acme-eab-permissions"
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["acm:RequestCertificate", "acm:RevokeCertificate"],
                        "Resource": "*",
                    }
                ],
            }
        ),
    )

    def _cleanup():
        try:
            iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup)
    return role_arn


def _create_binding_with_retry(ctx, acm, endpoint_arn, role_arn, timeout_s: float = 90.0, interval_s: float = 5.0):
    deadline = time.monotonic() + timeout_s
    last_err: ClientError | None = None
    while time.monotonic() < deadline:
        try:
            resp = acm.create_acme_external_account_binding(
                AcmeEndpointArn=endpoint_arn,
                RoleArn=role_arn,
                Tags=[{"Key": "sim2real", "Value": CHECK}],
            )
            return resp["ExternalAccountBinding"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException":
                raise
            last_err = exc
            time.sleep(interval_s)
    raise AssertionError(f"CreateAcmeExternalAccountBinding kept failing with AccessDeniedException: {last_err}")


def _pad(value: str) -> str:
    return value + "=" * (-len(value) % 4)


def _base64_decodable(value: str) -> bool:
    padded = _pad(value)
    for decoder in (base64.urlsafe_b64decode, base64.b64decode):
        try:
            decoder(padded)
            return True
        except (ValueError, TypeError):
            continue
    return False


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
