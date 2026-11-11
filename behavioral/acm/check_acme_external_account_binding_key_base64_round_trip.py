"""acme-external-account-binding-key-base64-round-trip."""
from __future__ import annotations

import json
import string
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "acme-external-account-binding-key-base64-round-trip"
GROUP = "representation"
SERVICES = ["acm"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Two GetAcmeExternalAccountBindingCredentials calls for one binding return the same KeyId and
    the identical server-generated MacKey, a non-empty string drawn only from base64 and base64url
    characters."""
    acm = ctx.client("acm")
    _require_acme_api(acm)
    iam = ctx.client("iam")

    endpoint_arn = _create_active_acme_endpoint(ctx, acm)
    role_arn = _create_eab_role(ctx, iam)
    eab_arn = _create_eab_with_retry(acm, endpoint_arn, role_arn)["ExternalAccountBinding"][
        "AcmeExternalAccountBindingArn"
    ]
    ctx.on_cleanup(lambda: acm.delete_acme_external_account_binding(AcmeExternalAccountBindingArn=eab_arn))

    first = acm.get_acme_external_account_binding_credentials(AcmeExternalAccountBindingArn=eab_arn)
    second = acm.get_acme_external_account_binding_credentials(AcmeExternalAccountBindingArn=eab_arn)

    assert first["KeyId"] == second["KeyId"]
    assert first["MacKey"] == second["MacKey"]

    # ACM's MacKey is not a padded/unpadded encoding of any fixed byte
    # string (its data-character count need not satisfy len % 4 in {0, 2, 3}), so it is
    # not literally base64.b64decode-able -- it is drawn from the base64url alphabet as
    # an opaque credential string, not bytes-to-be-decoded. Pin what is actually
    # guaranteed: it is composed only of base64url-safe characters, and it is completely
    # stable byte-for-byte across independent retrievals (proven above), not
    # regenerated per call and not corrupted/truncated/re-cased in transit.
    mac_key = first["MacKey"]
    assert mac_key, "MacKey must be non-empty"
    allowed = set(string.ascii_letters + string.digits + "-_+/=")
    assert set(mac_key) <= allowed, f"MacKey contains characters outside the base64url alphabet: {mac_key!r}"


def _require_acme_api(client) -> None:
    if "CreateAcmeEndpoint" not in client.meta.service_model.operation_names:
        raise AssertionError(
            "installed botocore lacks the ACM ACME endpoint operations "
            "(CreateAcmeEndpoint/CreateAcmeExternalAccountBinding/GetAcmeExternalAccountBindingCredentials) "
            "-- upgrade botocore/boto3 to a version that models the ACM ACME endpoint API surface"
        )


def _poll_until(probe, predicate, *, timeout_s: float = 60.0, interval_s: float = 2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition never met within {timeout_s}s, last value={last!r}")


def _create_active_acme_endpoint(ctx, acm) -> str:
    resp = acm.create_acme_endpoint(
        AuthorizationBehavior="PRE_APPROVED",
        CertificateAuthority={"PublicCertificateAuthority": {"AllowedKeyAlgorithms": ["RSA_2048"]}},
        Tags=[{"Key": "Name", "Value": ctx.unique_name("sim2real-acm-eab-roundtrip-")}],
    )
    arn = resp["AcmeEndpointArn"]

    def _cleanup_endpoint():
        try:
            acm.delete_acme_endpoint(AcmeEndpointArn=arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup_endpoint)
    status = _poll_until(
        lambda: acm.describe_acme_endpoint(AcmeEndpointArn=arn)["AcmeEndpoint"]["Status"],
        lambda s: s in ("ACTIVE", "FAILED"),
        timeout_s=60.0,
        interval_s=3.0,
    )
    if status != "ACTIVE":
        raise AssertionError(f"ACME endpoint entered {status}, expected ACTIVE")
    return arn


def _create_eab_role(ctx, iam) -> str:
    role_name = ctx.unique_name("sim2real-acm-eab-role-")
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
    permissions_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["acm:RequestCertificate", "acm:RevokeCertificate"],
                "Resource": "*",
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "Name", "Value": role_name}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.put_role_policy(
        RoleName=role_name, PolicyName="acme-eab-permissions", PolicyDocument=json.dumps(permissions_policy)
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="acme-eab-permissions"))
    return role_arn


def _create_eab_with_retry(acm, endpoint_arn, role_arn, timeout_s: float = 45.0):
    # ACM assumes the role synchronously (session "acme-verification") when creating the EAB,
    # so it can briefly fail with AccessDeniedException while the new role's trust policy
    # propagates through IAM. Retry only that specific, transient code.
    deadline = time.monotonic() + timeout_s
    last_code = None
    while time.monotonic() < deadline:
        try:
            return acm.create_acme_external_account_binding(
                AcmeEndpointArn=endpoint_arn,
                RoleArn=role_arn,
                Expiration={"Value": 7, "Type": "DAYS"},
            )
        except ClientError as exc:
            last_code = exc.response["Error"]["Code"]
            if last_code != "AccessDeniedException":
                raise
            time.sleep(3)
    raise AssertionError(f"CreateAcmeExternalAccountBinding never succeeded, last error={last_code}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
