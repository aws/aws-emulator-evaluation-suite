"""index-name-uppercase-rejected-lowercase-control-indexes."""
from __future__ import annotations

import random
import ssl
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "index-name-uppercase-rejected-lowercase-control-indexes"
GROUP = 'data-plane'
SERVICES = ['es']

_THROTTLE_CODES = ("ThrottlingException", "TooManyRequestsException", "RequestLimitExceeded")

MIN_CLUSTER_CONFIG = {
    "InstanceType": "t3.small.elasticsearch",
    "InstanceCount": 1,
}

MIN_EBS_OPTIONS = {
    "EBSEnabled": True,
    "VolumeType": "gp2",
    "VolumeSize": 10,
}

ELASTICSEARCH_VERSION = "7.10"

DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"


def _retry_throttled(fn, attempts: int = 8):
    """Call ``fn()``, retrying with backoff only on a throttle response."""
    for attempt in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") not in _THROTTLE_CODES or attempt == attempts - 1:
                raise
            time.sleep(4.0 * (1 + attempt) + random.uniform(0, 3.0))


def _ssl_context(verify):
    """An SSLContext honouring ``ctx.http_verify``: True, False, or a CA bundle path."""
    if verify is False:
        return ssl._create_unverified_context()
    return ssl.create_default_context(cafile=verify if isinstance(verify, str) else None)


def _signed_json_request(ctx, method: str, url: str, body=None):
    """Send a SigV4-signed ('es') HTTPS request to a domain endpoint.

    Signs with botocore (always available) and sends with stdlib urllib so the
    check needs no third-party HTTP client. Returns (status_code, parsed_json).
    """
    import json as _json
    import urllib.error
    import urllib.request

    from botocore.auth import SigV4Auth
    from botocore.awsrequest import AWSRequest

    signer_creds = ctx.client("es")._request_signer._credentials
    if signer_creds is None:
        raise AssertionError("no AWS credentials available to sign Elasticsearch data-plane requests")
    frozen = signer_creds.get_frozen_credentials()

    data = _json.dumps(body).encode() if body is not None else None
    headers = {"Content-Type": "application/json"} if data is not None else {}
    aws_req = AWSRequest(method=method, url=url, data=data, headers=headers)
    SigV4Auth(frozen, "es", ctx.region).add_auth(aws_req)

    req = urllib.request.Request(url, data=data, method=method, headers=dict(aws_req.headers))
    try:
        with urllib.request.urlopen(req, timeout=30, context=_ssl_context(ctx.http_verify)) as resp:
            raw = resp.read().decode()
            return resp.status, (_json.loads(raw) if raw else {})
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode(errors="replace")
        try:
            parsed = _json.loads(raw)
        except ValueError:
            parsed = {"raw": raw}
        return exc.code, parsed
    except (urllib.error.URLError, OSError) as exc:
        raise AssertionError(
            f"{DATAPLANE_MARKER}: signed {method} to the domain endpoint did not complete: "
            f"{type(exc).__name__}: {exc}"
        ) from exc


def _searchable_domain_access_policy(ctx, domain_name: str) -> str:
    """An access policy allowing the caller's own account to use the data plane."""
    import json as _json

    account_id = ctx.account
    arn = f"arn:aws:es:{ctx.region}:{account_id}:domain/{domain_name}"
    return _json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
            "Action": "es:*",
            "Resource": f"{arn}/*",
        }],
    })


def _wait_domain_searchable(ctx, domain_name: str, timeout_s: float = 1800):
    """Poll until the domain is done Processing AND has published an Endpoint."""
    es = ctx.client("es")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            status = es.describe_elasticsearch_domain(DomainName=domain_name)["DomainStatus"]
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") not in _THROTTLE_CODES:
                raise
            time.sleep(2)
            continue
        last = status
        if status.get("Processing") is False and status.get("Endpoint"):
            return status["Endpoint"]
        time.sleep(5)
    detail = (
        f"domain {domain_name} never became searchable within {timeout_s}s "
        f"(last Processing={last.get('Processing') if last else '?'}, "
        f"Endpoint={last.get('Endpoint') if last else '?'})"
    )
    raise AssertionError(detail)


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "concern:data-plane",
      "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """Indexing into an uppercase index name is rejected invalid_index_name_exception,
    leaving it absent, while a lowercase index on the same domain indexes and is found.

    Reference: https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/es-indexing.html
    """
    es = ctx.client("es")

    domain_name = ctx.unique_name("sim2real-behav-es-")[:28].rstrip("-")
    _retry_throttled(lambda: es.create_elasticsearch_domain(
        DomainName=domain_name,
        ElasticsearchVersion=ELASTICSEARCH_VERSION,
        ElasticsearchClusterConfig=dict(MIN_CLUSTER_CONFIG),
        EBSOptions=dict(MIN_EBS_OPTIONS),
        AccessPolicies=_searchable_domain_access_policy(ctx, domain_name),
    ))
    ctx.on_cleanup(lambda: es.delete_elasticsearch_domain(DomainName=domain_name))

    endpoint = _wait_domain_searchable(ctx, domain_name)
    base = ctx.endpoint_url(endpoint)
    _dp_deadline = time.monotonic() + 300
    while time.monotonic() < _dp_deadline:
        _st, _ = _signed_json_request(ctx, "GET", f"{base}/")
        if _st != 403:
            break
        time.sleep(2)

    bad_index = "UPPER-" + ctx.unique_name("sim2real-behav-idx-")[-8:]
    doc = {"title": "sim2real"}

    status, body = _signed_json_request(ctx, "PUT", f"{base}/{bad_index}/_doc/1", doc)
    err = body.get("error") if isinstance(body, dict) else None
    assert status == 400 and isinstance(err, dict) and err.get("type") == "invalid_index_name_exception", (
        f"PUT _doc into an uppercase index name expected 400 invalid_index_name_exception, "
        f"got HTTP {status}: {body}"
    )
    assert err.get("reason") == f"Invalid index name [{bad_index}], must be lowercase", (
        f"invalid_index_name_exception reason expected to name {bad_index!r} and require "
        f"lowercase, got {err.get('reason')!r}"
    )

    status, got = _signed_json_request(ctx, "GET", f"{base}/{bad_index.lower()}/_doc/1")
    body_err = got.get("error") if isinstance(got, dict) else None
    is_absent = (
        status == 404 and isinstance(body_err, dict) and body_err.get("type") == "index_not_found_exception"
    )
    assert is_absent, (
        f"the rejected uppercase index must not have been created (checked lowercased form), "
        f"got HTTP {status}: {got}"
    )

    good_index = ctx.unique_name("sim2real-behav-idx-")
    status, _ = _signed_json_request(ctx, "PUT", f"{base}/{good_index}/_doc/1", doc)
    assert status in (200, 201), f"positive control: indexing document failed with HTTP {status}"

    status, _ = _signed_json_request(ctx, "POST", f"{base}/{good_index}/_refresh")
    assert status == 200, f"positive control: index refresh failed with HTTP {status}"

    status, result = _signed_json_request(
        ctx, "POST", f"{base}/{good_index}/_search", {"query": {"match": {"title": "sim2real"}}}
    )
    assert status == 200, f"positive control: _search failed with HTTP {status}: {result}"
    total = result.get("hits", {}).get("total", {})
    total_value = total.get("value") if isinstance(total, dict) else total
    assert total_value and total_value >= 1, (
        f"positive control: lowercase index should be searchable, got {result.get('hits')}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
