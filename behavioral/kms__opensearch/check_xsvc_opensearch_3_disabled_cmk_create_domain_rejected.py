"""xsvc-opensearch-3-disabled-cmk-create-domain-rejected."""
from __future__ import annotations

import random
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "xsvc-opensearch-3-disabled-cmk-create-domain-rejected"
GROUP = 'kms-encryption-at-rest-rejected'
SERVICES = ['kms', 'opensearch']

_THROTTLE_CODES = ("ThrottlingException", "TooManyRequestsException", "RequestLimitExceeded")
ENGINE_VERSION = "OpenSearch_2.11"
MIN_CLUSTER_CONFIG = {"InstanceType": "t3.small.search", "InstanceCount": 1}
MIN_EBS_OPTIONS = {"EBSEnabled": True, "VolumeType": "gp3", "VolumeSize": 10}


class _Accepted(Exception):
    """The call that real AWS rejects was accepted; carries the response."""

    def __init__(self, response):
        super().__init__("call unexpectedly succeeded")
        self.response = response


def _call(fn):
    """Return (code, message, http_status) of the ClientError fn raises; raise _Accepted if it
    succeeds, so an accepted call can never read as an error-code mismatch. Throttles retry."""
    for attempt in range(12):
        try:
            resp = fn()
        except ClientError as exc:
            err = exc.response.get("Error", {})
            if err.get("Code") in _THROTTLE_CODES:
                time.sleep(6.0 * (1 + attempt) + random.uniform(0, 6.0))
                continue
            return (err.get("Code"), err.get("Message"),
                    exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode"))
        raise _Accepted(resp)
    raise AssertionError("still throttled after 12 attempts")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:e2e", "plane:control")
def run(ctx) -> None:
    """CreateDomain naming a DISABLED customer-managed key is rejected, no domain is created, and
    re-enabling that same key makes the identical request succeed.
    """
    osc = ctx.client("opensearch")
    kms = ctx.client("kms")
    domain = ctx.unique_name("sim2real-xkd-")[:28].rstrip("-")

    key = kms.create_key(
        Description=f"sim2real-xsvc {CHECK}",
        Tags=[{"TagKey": "sim2real", "TagValue": CHECK}],
    )["KeyMetadata"]
    key_arn = key["Arn"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key["KeyId"], PendingWindowInDays=7))
    kms.disable_key(KeyId=key["KeyId"])
    state = kms.describe_key(KeyId=key["KeyId"])["KeyMetadata"]["KeyState"]
    assert state == "Disabled", f"precondition: key state is {state!r} after DisableKey"

    request = dict(
        DomainName=domain,
        EngineVersion=ENGINE_VERSION,
        ClusterConfig=dict(MIN_CLUSTER_CONFIG),
        EBSOptions=dict(MIN_EBS_OPTIONS),
        EncryptionAtRestOptions={"Enabled": True, "KmsKeyId": key_arn},
        TagList=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    try:
        code, message, status = _call(lambda: osc.create_domain(**request))
    except _Accepted as acc:
        ctx.on_cleanup(lambda: osc.delete_domain(DomainName=domain))
        raise AssertionError(
            f"CreateDomain with DISABLED key {key_arn!r} was accepted: "
            f"{acc.response.get('DomainStatus', {}).get('ARN')!r}"
        ) from None
    assert code == "ValidationException", (
        f"CreateDomain with a disabled CMK raised {code!r} ({message!r}), expected ValidationException"
    )
    expected = f"Error in Accessing KmsKeyID with details:KmsKeyID:{key_arn} is not in Enabled State"
    assert message == expected, f"rejection message was {message!r}, expected {expected!r}"
    assert status == 400, f"rejection HTTP status was {status!r}, expected 400"

    try:
        miss = _call(lambda: osc.describe_domain(DomainName=domain))
    except _Accepted as acc:
        ctx.on_cleanup(lambda: osc.delete_domain(DomainName=domain))
        raise AssertionError(
            f"a rejected CreateDomain still produced domain {domain!r}: {acc.response!r}"
        ) from None
    assert miss[0] == "ResourceNotFoundException", (
        f"DescribeDomain after the rejection raised {miss!r}, expected ResourceNotFoundException"
    )
    assert miss[1] == f"Domain not found: {domain}", (
        f"DescribeDomain not-found message was {miss[1]!r}, expected 'Domain not found: {domain}'"
    )

    # Positive control: the ONLY change is EnableKey; the identical request now succeeds.
    kms.enable_key(KeyId=key["KeyId"])
    state = kms.describe_key(KeyId=key["KeyId"])["KeyMetadata"]["KeyState"]
    assert state == "Enabled", f"key state is {state!r} after EnableKey"
    status_doc = None
    for attempt in range(12):
        try:
            status_doc = osc.create_domain(**request)["DomainStatus"]
            break
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") not in _THROTTLE_CODES:
                raise AssertionError(
                    f"positive control: CreateDomain with the re-enabled key failed: "
                    f"{exc.response.get('Error')!r}"
                ) from None
            time.sleep(6.0 * (1 + attempt) + random.uniform(0, 6.0))
    assert status_doc is not None, "positive control: CreateDomain still throttled after 12 attempts"
    ctx.on_cleanup(lambda: osc.delete_domain(DomainName=domain))
    # Only the two members the request set are graded; AWS also echoes server-chosen members.
    ear = {k: (status_doc.get("EncryptionAtRestOptions") or {}).get(k)
           for k in ("Enabled", "KmsKeyId")}
    assert ear == {"Enabled": True, "KmsKeyId": key_arn}, (
        f"positive control: accepted domain echoed EncryptionAtRestOptions {ear!r}"
    )
    assert status_doc.get("DomainName") == domain, (
        f"positive control: accepted domain is named {status_doc.get('DomainName')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
