"""put-policy-document-round-trip."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-policy-document-round-trip"
GROUP = "representation"
SERVICES = ["acm-pca"]

_KEY_ALGORITHM = "RSA_2048"
_SIGNING_ALGORITHM = "SHA256WITHRSA"


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetPolicy returns a compactly serialized PutPolicy document with the same
    statements, actions, conditions, principal and resource: the service preserves
    the policy's meaning, not merely its bytes."""
    client = ctx.client("acm-pca")
    arn = _create_ca(ctx)
    ctx.on_cleanup(lambda: _best_effort_delete(ctx, arn))
    _wait_for_status(ctx, arn, {"PENDING_CERTIFICATE"}, timeout_s=90)

    # Use the caller's own (real, existing) account as principal -- PutPolicy is
    # granting cross-account access and a bogus/non-existent account number is not
    # what we want to exercise here (that's a separate validation concern).
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowDescribeAndGet",
                "Effect": "Allow",
                "Principal": {"AWS": account_id},
                "Action": [
                    "acm-pca:DescribeCertificateAuthority",
                    "acm-pca:GetCertificate",
                    "acm-pca:GetCertificateAuthorityCertificate",
                    "acm-pca:ListPermissions",
                    "acm-pca:ListTags",
                ],
                "Resource": arn,
            },
            {
                "Sid": "AllowIssueWithTemplate",
                "Effect": "Allow",
                "Principal": {"AWS": account_id},
                "Action": ["acm-pca:IssueCertificate"],
                "Resource": arn,
                "Condition": {
                    "StringEquals": {
                        "acm-pca:TemplateArn": "arn:aws:acm-pca:::template/EndEntityCertificate/V1"
                    }
                },
            },
        ],
    }
    # Compact separators and dict-insertion key order deliberately differ from any
    # "canonical" pretty-printed form the backend might re-serialize to.
    submitted = json.dumps(policy_doc, separators=(",", ":"))

    client.put_policy(ResourceArn=arn, Policy=submitted)
    fetched = client.get_policy(ResourceArn=arn)["Policy"]
    parsed_fetched = json.loads(fetched)

    # The service is free to canonicalize scalar-vs-list encodings (e.g. a single
    # "Resource" string may come back as a one-element list, likewise for
    # "Action"/"Principal.AWS") -- that is a representation normalization, not a
    # semantic drift. Normalize both sides the same way before comparing so the
    # assertion targets *meaning* (statements, actions, conditions, principal,
    # resource) rather than the literal scalar/list shape IAM chooses to echo.
    assert _normalize_policy(parsed_fetched) == _normalize_policy(policy_doc), (
        f"policy round trip drifted: {parsed_fetched!r} != {policy_doc!r}"
    )


def _as_sorted_list(value):
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return sorted(value)
    return value


def _normalize_account_ref(value: str) -> str:
    # A principal account may be echoed back as a bare account id ("123456789012")
    # or as the equivalent root-user ARN ("arn:aws:iam::123456789012:root") -- both
    # denote the same principal.
    if value.startswith("arn:") and ":iam::" in value:
        try:
            return value.split(":iam::", 1)[1].split(":", 1)[0]
        except IndexError:
            return value
    return value


def _normalize_principal(value):
    if isinstance(value, dict):
        out = {}
        for k, v in value.items():
            items = _as_sorted_list(v)
            if isinstance(items, list):
                items = sorted(_normalize_account_ref(i) for i in items)
            out[k] = items
        return out
    return _as_sorted_list(value)


def _normalize_condition(value):
    if not isinstance(value, dict):
        return value
    out = {}
    for op, kv in value.items():
        if isinstance(kv, dict):
            out[op] = {k: _as_sorted_list(v) for k, v in kv.items()}
        else:
            out[op] = kv
    return out


def _normalize_statement(stmt: dict) -> dict:
    out = dict(stmt)
    for key in ("Action", "NotAction", "Resource", "NotResource"):
        if key in out:
            out[key] = _as_sorted_list(out[key])
    for key in ("Principal", "NotPrincipal"):
        if key in out:
            out[key] = _normalize_principal(out[key])
    if "Condition" in out:
        out["Condition"] = _normalize_condition(out["Condition"])
    return out


def _normalize_policy(doc: dict) -> dict:
    out = dict(doc)
    statements = out.get("Statement")
    if isinstance(statements, dict):
        statements = [statements]
    if isinstance(statements, list):
        normalized = [_normalize_statement(s) for s in statements]
        out["Statement"] = sorted(normalized, key=lambda s: s.get("Sid", ""))
    return out


def _describe_status(ctx, arn: str) -> str:
    client = ctx.client("acm-pca")
    return client.describe_certificate_authority(CertificateAuthorityArn=arn)["CertificateAuthority"]["Status"]


def _wait_for_status(ctx, arn, target_statuses, timeout_s=90.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = _describe_status(ctx, arn)
        if last in target_statuses:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"status never reached {target_statuses}, last seen {last}")


def _create_ca(ctx, ca_type: str = "ROOT") -> str:
    client = ctx.client("acm-pca")
    cn = ctx.unique_name("sim2real-pca-")[:64]
    resp = client.create_certificate_authority(
        CertificateAuthorityConfiguration={
            "KeyAlgorithm": _KEY_ALGORITHM,
            "SigningAlgorithm": _SIGNING_ALGORITHM,
            "Subject": {"CommonName": cn},
        },
        CertificateAuthorityType=ca_type,
        Tags=[{"Key": "sim2real", "Value": "put-policy-document-round-trip"}],
    )
    return resp["CertificateAuthorityArn"]


def _best_effort_delete(ctx, arn: str) -> None:
    client = ctx.client("acm-pca")
    try:
        status = _describe_status(ctx, arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFoundException":
            return
        raise
    if status == "DELETED":
        return
    try:
        client.delete_policy(ResourceArn=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    if status == "ACTIVE":
        client.update_certificate_authority(CertificateAuthorityArn=arn, Status="DISABLED")
        _wait_for_status(ctx, arn, {"DISABLED"}, timeout_s=60)
    client.delete_certificate_authority(CertificateAuthorityArn=arn, PermanentDeletionTimeInDays=7)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
