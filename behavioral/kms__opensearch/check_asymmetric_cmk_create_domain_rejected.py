"""asymmetric-cmk-create-domain-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "asymmetric-cmk-create-domain-rejected"
GROUP = "encryption-at-rest-key-type"
SERVICES = ["kms", "opensearch"]

_THROTTLE = ("ThrottlingException", "TooManyRequestsException", "RequestLimitExceeded")
_BACKOFF_DEADLINE_S = 90


def _domain_request(name: str, key_arn: str) -> dict:
    return {
        "DomainName": name,
        "EngineVersion": "OpenSearch_2.11",
        "ClusterConfig": {"InstanceType": "t3.small.search", "InstanceCount": 1},
        "EBSOptions": {"EBSEnabled": True, "VolumeType": "gp3", "VolumeSize": 10},
        "EncryptionAtRestOptions": {"Enabled": True, "KmsKeyId": key_arn},
        "TagList": [{"Key": "sim2real", "Value": CHECK}],
    }


def _create_with_backoff(osc, request: dict) -> dict:
    """CreateDomain's DomainStatus, retrying only AWS's documented throttle codes."""
    deadline = time.monotonic() + _BACKOFF_DEADLINE_S
    while True:
        try:
            return osc.create_domain(**request)["DomainStatus"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in _THROTTLE or time.monotonic() > deadline:
                raise
            time.sleep(5.0)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:e2e", "plane:control")
def run(ctx) -> None:
    """CreateDomain naming an asymmetric (RSA) KMS key for encryption at rest is rejected, no
    domain is created, and the identical request with a symmetric key is accepted.
    """
    osc = ctx.client("opensearch")
    kms = ctx.client("kms")
    name = ctx.unique_name("sim2real-xka-")[:28].rstrip("-")

    rsa_key = kms.create_key(
        Description=f"sim2real {CHECK}",
        KeySpec="RSA_2048",
        KeyUsage="SIGN_VERIFY",
        Tags=[{"TagKey": "sim2real", "TagValue": CHECK}],
    )["KeyMetadata"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=rsa_key["KeyId"], PendingWindowInDays=7))
    assert rsa_key["KeySpec"] == "RSA_2048", f"precondition: created key spec is {rsa_key['KeySpec']!r}"

    accepted_rsa = None
    try:
        accepted_rsa = _create_with_backoff(osc, _domain_request(name, rsa_key["Arn"]))
    except ClientError as exc:
        err = exc.response["Error"]
        want = (
            "ValidationException",
            f"Error in Accessing KmsKeyID with details:KmsKeyID:{rsa_key['Arn']} is not a "
            "Symmetric CMK. Only Symmetric CMKs may be used for encryption at rest.",
        )
        got = (err.get("Code"), err.get("Message"))
        assert got == want, f"CreateDomain with an asymmetric key raised {got!r}, expected {want!r}"
    if accepted_rsa is not None:
        ctx.on_cleanup(lambda: osc.delete_domain(DomainName=name))
        raise AssertionError(
            f"CreateDomain with the asymmetric key {rsa_key['Arn']!r} was accepted: "
            f"{accepted_rsa.get('ARN')!r}"
        )

    try:
        found = osc.describe_domain(DomainName=name)
    except ClientError as exc:
        err = exc.response["Error"]
        want_absent = ("ResourceNotFoundException", f"Domain not found: {name}")
        got_absent = (err.get("Code"), err.get("Message"))
        assert got_absent == want_absent, (
            f"DescribeDomain after the rejection raised {got_absent!r}, expected {want_absent!r}"
        )
    else:
        raise AssertionError(f"a rejected CreateDomain still produced domain {name!r}: {found!r}")

    # Positive control: swap in a symmetric key and change nothing else.
    aes_key = kms.create_key(
        Description=f"sim2real {CHECK} control",
        Tags=[{"TagKey": "sim2real", "TagValue": CHECK}],
    )["KeyMetadata"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=aes_key["KeyId"], PendingWindowInDays=7))
    assert aes_key["KeySpec"] == "SYMMETRIC_DEFAULT", (
        f"control precondition: key spec is {aes_key['KeySpec']!r}"
    )

    accepted = _create_with_backoff(osc, _domain_request(name, aes_key["Arn"]))
    ctx.on_cleanup(lambda: osc.delete_domain(DomainName=name))
    echoed_key = (accepted.get("EncryptionAtRestOptions") or {}).get("KmsKeyId")
    assert echoed_key == aes_key["Arn"], (
        f"the accepted domain echoed KmsKeyId {echoed_key!r}, expected the symmetric key "
        f"{aes_key['Arn']!r}"
    )
    assert accepted.get("DomainName") == name, (
        f"the accepted domain is named {accepted.get('DomainName')!r}, expected {name!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
