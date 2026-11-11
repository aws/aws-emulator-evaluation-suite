"""xsvc-opensearch-3-cmk-domain-echoes-key-grants-and-serves-search."""
from __future__ import annotations

import json
import random
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "xsvc-opensearch-3-cmk-domain-echoes-key-grants-and-serves-search"
GROUP = 'kms-encryption-at-rest'
SERVICES = ['kms', 'opensearch']

_THROTTLE_CODES = ("ThrottlingException", "TooManyRequestsException", "RequestLimitExceeded")
ENGINE_VERSION = "OpenSearch_2.11"
MIN_CLUSTER_CONFIG = {"InstanceType": "t3.small.search", "InstanceCount": 1}
MIN_EBS_OPTIONS = {"EBSEnabled": True, "VolumeType": "gp3", "VolumeSize": 10}
# Prefix for failures where the domain endpoint never answered.
DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"


def _create_domain(osc, **kwargs):
    """CreateDomain with a bounded backoff on throttling only; every other error propagates."""
    for attempt in range(12):
        try:
            return osc.create_domain(**kwargs)["DomainStatus"]
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") not in _THROTTLE_CODES:
                raise
            time.sleep(6.0 * (1 + attempt) + random.uniform(0, 6.0))
    raise AssertionError("CreateDomain still throttled after 12 attempts")


def _account_policy(account_id: str, region: str, domain: str) -> str:
    arn = f"arn:aws:es:{region}:{account_id}:domain/{domain}"
    return json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
            "Action": "es:*",
            "Resource": f"{arn}/*",
        }],
    })


def _signed_json_request(ctx, method: str, url: str, body=None):
    """Send a SigV4 ('es') HTTPS request to the domain endpoint; return (status, parsed_json).

    Signs with ctx's credentials, never the ambient chain; a transport failure raises.
    """
    import urllib.error
    import urllib.request

    from botocore.auth import SigV4Auth
    from botocore.awsrequest import AWSRequest

    signer_creds = ctx.client("opensearch")._request_signer._credentials
    if signer_creds is None:
        raise AssertionError("no AWS credentials available to sign OpenSearch data-plane requests")
    frozen = signer_creds.get_frozen_credentials()
    data = json.dumps(body).encode() if body is not None else None
    headers = {"Content-Type": "application/json"} if data is not None else {}
    aws_req = AWSRequest(method=method, url=url, data=data, headers=headers)
    SigV4Auth(frozen, "es", ctx.region).add_auth(aws_req)
    req = urllib.request.Request(url, data=data, method=method, headers=dict(aws_req.headers))
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            raw = resp.read().decode()
            return resp.status, (json.loads(raw) if raw else {})
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode(errors="replace")
        try:
            return exc.code, json.loads(raw)
        except ValueError:
            return exc.code, {"raw": raw}
    except (urllib.error.URLError, ConnectionError, TimeoutError) as exc:
        raise AssertionError(
            f"{DATAPLANE_MARKER}: signed {method} to the domain endpoint did not complete: "
            f"{type(exc).__name__}: {exc}"
        ) from exc


def _wait_searchable(osc, domain: str, timeout_s: float = 1800) -> str:
    deadline = time.monotonic() + timeout_s
    last = {}
    while time.monotonic() < deadline:
        last = osc.describe_domain(DomainName=domain)["DomainStatus"]
        if last.get("Processing") is False and last.get("Endpoint"):
            return last["Endpoint"]
        time.sleep(2)
    detail = (f"domain {domain} never became searchable within {timeout_s}s "
              f"(Processing={last.get('Processing')!r}, Endpoint={last.get('Endpoint')!r})")
    raise AssertionError(detail)


def _all_grants(kms, key_id: str) -> list:
    grants, marker = [], None
    while True:
        kw = {"KeyId": key_id}
        if marker:
            kw["Marker"] = marker
        page = kms.list_grants(**kw)
        grants.extend(page.get("Grants", []))
        if not page.get("Truncated"):
            return grants
        marker = page["NextMarker"]


@tags(
    "axis:happy-path",
    "cap:c2",
    "concern:data-plane",
    "concern:e2e",
    "concern:representation",
    "dp:endpoint",
    "plane:data",
)
def run(ctx) -> None:
    """A domain encrypted at rest with a CMK echoes the key, OpenSearch's regional service principal
    takes a Decrypt/GenerateDataKey grant on it scoped to this domain's ARN, and the domain serves
    a signed _search returning the indexed document.
    """
    osc = ctx.client("opensearch")
    kms = ctx.client("kms")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    domain = ctx.unique_name("sim2real-xk-")[:28].rstrip("-")
    domain_arn = f"arn:aws:es:{ctx.region}:{account_id}:domain/{domain}"

    key = kms.create_key(
        Description=f"sim2real-xsvc {CHECK}",
        Tags=[{"TagKey": "sim2real", "TagValue": CHECK}],
    )["KeyMetadata"]
    key_arn = key["Arn"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key["KeyId"], PendingWindowInDays=7))
    assert key["KeyManager"] == "CUSTOMER", f"created key is not customer-managed: {key!r}"

    created = _create_domain(
        osc,
        DomainName=domain,
        EngineVersion=ENGINE_VERSION,
        ClusterConfig=dict(MIN_CLUSTER_CONFIG),
        EBSOptions=dict(MIN_EBS_OPTIONS),
        EncryptionAtRestOptions={"Enabled": True, "KmsKeyId": key_arn},
        AccessPolicies=_account_policy(account_id, ctx.region, domain),
        TagList=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: osc.delete_domain(DomainName=domain))

    ear = created.get("EncryptionAtRestOptions") or {}
    assert ear.get("Enabled") is True and ear.get("KmsKeyId") == key_arn, (
        f"CreateDomain echoed EncryptionAtRestOptions {ear!r}, expected the CMK {key_arn!r}"
    )
    assert ear.get("EncryptionMode") in (None, "DISK", "NATIVE"), (
        f"CreateDomain echoed an undocumented EncryptionMode {ear.get('EncryptionMode')!r}"
    )
    described = osc.describe_domain(DomainName=domain)["DomainStatus"]
    d_ear = described.get("EncryptionAtRestOptions") or {}
    assert d_ear.get("Enabled") is True and d_ear.get("KmsKeyId") == key_arn, (
        f"DescribeDomain returned EncryptionAtRestOptions {d_ear!r}, expected KmsKeyId {key_arn!r}"
    )

    # Polled, because grant creation is asynchronous.
    service_principal = f"es.{ctx.region}.amazonaws.com"
    deadline = time.monotonic() + 600
    ours: list = []
    grants: list = []
    while time.monotonic() < deadline:
        grants = _all_grants(kms, key["KeyId"])
        ours = [
            g for g in grants
            if g.get("GranteePrincipal") == service_principal
            and ((g.get("Constraints") or {}).get("EncryptionContextSubset") or {}).get("domainARN")
            == domain_arn
        ]
        if ours:
            break
        time.sleep(2)
    assert ours, (
        f"no KMS grant to {service_principal!r} constrained to domainARN={domain_arn!r} appeared "
        f"on {key_arn!r} within 600s; grants were {grants!r}"
    )
    for g in ours:
        ops = set(g.get("Operations") or [])
        assert {"Decrypt", "GenerateDataKey"} <= ops, (
            f"OpenSearch's grant {g.get('GrantId')!r} lacks Decrypt/GenerateDataKey: {sorted(ops)!r}"
        )
        assert g.get("RetiringPrincipal") == service_principal, (
            f"grant {g.get('GrantId')!r} retiring principal is {g.get('RetiringPrincipal')!r}, "
            f"expected {service_principal!r}"
        )
        assert g.get("IssuingAccount") == f"arn:aws:iam::{account_id}:root", (
            f"grant {g.get('GrantId')!r} issued by {g.get('IssuingAccount')!r}"
        )

    endpoint = _wait_searchable(osc, domain)
    active = osc.describe_domain(DomainName=domain)["DomainStatus"]
    assert (active.get("EncryptionAtRestOptions") or {}).get("KmsKeyId") == key_arn, (
        f"KmsKeyId drifted after activation: {active.get('EncryptionAtRestOptions')!r}"
    )
    base = ctx.endpoint_url(endpoint)
    dp_deadline = time.monotonic() + 300
    st = None
    while time.monotonic() < dp_deadline:
        st, _ = _signed_json_request(ctx, "GET", f"{base}/")
        if st != 403:
            break
        time.sleep(2)
    assert st == 200, f"signed GET / on the CMK-encrypted domain returned HTTP {st!r}"

    index = ctx.unique_name("sim2real-cmk-idx-")
    marker = ctx.unique_name("cmk-")
    st, body = _signed_json_request(ctx, "PUT", f"{base}/{index}/_doc/1",
                                    {"title": "encrypted at rest", "marker": marker})
    assert st == 201, f"indexing into the CMK-encrypted domain returned HTTP {st!r}: {body!r}"
    st, body = _signed_json_request(ctx, "POST", f"{base}/{index}/_refresh")
    assert st == 200, f"_refresh returned HTTP {st!r}: {body!r}"
    st, body = _signed_json_request(ctx, "POST", f"{base}/{index}/_search",
                                    {"query": {"term": {"marker.keyword": marker}}})
    assert st == 200, f"_search returned HTTP {st!r}: {body!r}"
    hits = (body.get("hits") or {}).get("hits") or []
    assert [h.get("_source", {}).get("marker") for h in hits] == [marker], (
        f"_search for marker {marker!r} returned {hits!r}, expected exactly the one indexed doc"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
