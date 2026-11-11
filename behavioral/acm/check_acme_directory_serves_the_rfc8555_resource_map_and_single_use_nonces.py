"""acme-directory-serves-the-rfc8555-resource-map-and-single-use-nonces."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags


def _routed_request(ctx, url, data=None, headers=None, **kwargs):
    """A urllib Request that reaches ``url`` on the target, with ``ctx.endpoint_route``'s headers."""
    target, route = ctx.endpoint_route(url)
    return urllib.request.Request(target, data=data, headers={**(headers or {}), **route}, **kwargs)


CHECK = "acme-directory-serves-the-rfc8555-resource-map-and-single-use-nonces"
GROUP = "data-plane"
SERVICES = ["acm"]

# RFC 8555 §7.1.1: the directory object's REQUIRED members. `newAuthz` is optional (it is
# required only of servers that support pre-authorization) and is deliberately excluded.
_RFC8555_REQUIRED_RESOURCES = ("newNonce", "newAccount", "newOrder", "revokeCert", "keyChange")

# ===== helpers (self-contained) =====

_THROTTLE_CODES = (
    "ThrottlingException",
    "Throttling",
    "TooManyRequestsException",
    "RequestInProgressException",
)


def _retry_throttle(fn, attempts=7, base_delay=4.0):
    """Retry fn() on ACM throttle codes (test-infra robustness, not a behavioral assertion)."""
    last = None
    for i in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") not in _THROTTLE_CODES:
                raise
            last = exc
            time.sleep(base_delay * (i + 1))
    raise last


def _http(ctx, url, *, data=None, headers=None, method=None):
    """One HTTP round trip, returning (status, lower-cased headers, body).

    An HTTP error STATUS is a value this check grades, so HTTPError is converted rather than
    propagated. A transport failure (URLError, timeout) is NOT caught: an ACME endpoint that
    cannot be reached at all is a failure, not a status code.
    """
    request = _routed_request(ctx, url, data=data, headers=headers or {}, method=method)
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            return (response.status,
                    {k.lower(): v for k, v in response.headers.items()},
                    response.read())
    except urllib.error.HTTPError as exc:
        return exc.code, {k.lower(): v for k, v in exc.headers.items()}, exc.read()


def _poll_until(probe, predicate, *, timeout_s, interval_s, description):
    """Poll probe() until predicate(result); RAISE on deadline (never return the last value)."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _safe_delete_endpoint(acm, arn):
    """Teardown only. Not an assertion path: a still-DELETING endpoint is not this check's
    subject, and a NotFound here means the endpoint is already gone."""
    acm.delete_acme_endpoint(AcmeEndpointArn=arn)


def _active_endpoint(ctx, acm):
    """Create an ACME endpoint and return (arn, EndpointUrl) once it is ACTIVE.

    Created in-check and torn down here, so the check works against an account that has no
    ACME endpoint at all.
    """
    arn = _retry_throttle(lambda: acm.create_acme_endpoint(
        AuthorizationBehavior="PRE_APPROVED",
        CertificateAuthority={"PublicCertificateAuthority": {
            "AllowedKeyAlgorithms": ["RSA_2048", "EC_prime256v1", "EC_secp384r1"]}},
        Contact="NOT_REQUIRED",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    ))["AcmeEndpointArn"]
    ctx.on_cleanup(lambda: _safe_delete_endpoint(acm, arn))

    def _describe():
        return _retry_throttle(
            lambda: acm.describe_acme_endpoint(AcmeEndpointArn=arn))["AcmeEndpoint"]

    endpoint = _poll_until(
        _describe,
        # The terminal set must not admit the failure value: FAILED is raised on, not
        # accepted, so the poll can never terminate on the state the check exists to exclude.
        lambda ep: ep["Status"] == "ACTIVE" or _raise_if_failed(ep),
        timeout_s=240, interval_s=5,
        description="the ACME endpoint reaching ACTIVE so its directory is served",
    )
    return arn, endpoint["EndpointUrl"]


def _raise_if_failed(endpoint):
    assert endpoint["Status"] != "FAILED", (
        "the ACME endpoint entered FAILED and will never serve a directory: "
        f"{endpoint.get('FailureReason')!r}"
    )
    return False


def _new_nonce(ctx, new_nonce_url, *, method):
    """One fetch of the newNonce resource, returning (status, headers)."""
    status, headers, body = _http(ctx, new_nonce_url, method=method)
    assert body == b"" or method == "HEAD", (
        f"RFC 8555 §7.2 requires an EMPTY body from GET {new_nonce_url!r}; got {body[:120]!r}"
    )
    return status, headers


# ===== end helpers =====


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """The ACME endpoint ACM provisions serves an RFC 8555 directory over HTTPS whose resource
    URLs derive from the endpoint's own URL, and whose newNonce hands out unrepeated nonces with
    Cache-Control: no-store, so the endpoint is a working ACME server and not a stored URL.
    Reference: https://docs.aws.amazon.com/acm/latest/userguide/acm-acme-endpoints.html
    """
    acm = ctx.client("acm")
    endpoint_arn, directory_url = _active_endpoint(ctx, acm)

    # (1) The directory URL is served -- by an HTTP server, not by the AWS API.
    status, headers, body = _http(ctx, directory_url)
    assert status == 200, (
        f"the ACME directory at {directory_url!r} must be served; got HTTP {status} with body "
        f"{body[:200]!r}"
    )
    content_type = headers.get("content-type", "<absent>")
    assert content_type.split(";")[0].strip() == "application/json", (
        f"the ACME directory must be JSON; Content-Type is {content_type!r}"
    )
    directory = json.loads(body)
    assert isinstance(directory, dict), (
        f"RFC 8555 §7.1.1 defines the directory as a JSON object; got {type(directory).__name__}"
    )

    # (2) Every RFC-required resource is present.
    missing = [name for name in _RFC8555_REQUIRED_RESOURCES if name not in directory]
    assert not missing, (
        f"the ACME directory at {directory_url!r} is missing RFC 8555 §7.1.1 required "
        f"resources {missing}; it advertises {sorted(directory)}"
    )

    # (3) Each resource URL is DERIVED from this endpoint's own directory URL -- same scheme,
    #     same host, same per-endpoint path prefix. A recording of a different endpoint's
    #     directory cannot satisfy this, and neither can a fixed-host stub.
    assert directory_url.endswith("/directory"), (
        f"DescribeAcmeEndpoint's EndpointUrl must be the ACME directory resource; got "
        f"{directory_url!r}"
    )
    prefix = directory_url[: -len("directory")]
    assert not (p := ctx.published_url_mismatch(directory_url, labels=(ctx.region,))), p
    for name in _RFC8555_REQUIRED_RESOURCES:
        url = directory[name]
        assert isinstance(url, str) and url.startswith(prefix), (
            f"the directory's {name!r} resource must live under this endpoint's own prefix "
            f"{prefix!r}; got {url!r}"
        )


    # (5) HEAD newNonce: RFC 8555 §7.2's status, nonce and cache directive.
    new_nonce_url = directory["newNonce"]
    head_status, head_headers = _new_nonce(ctx, new_nonce_url, method="HEAD")
    assert head_status == 200, (
        f"RFC 8555 §7.2: HEAD {new_nonce_url!r} must answer 200; got {head_status}"
    )
    first_nonce = head_headers.get("replay-nonce", "")
    assert first_nonce, (
        f"HEAD {new_nonce_url!r} must carry a Replay-Nonce header; headers were "
        f"{sorted(head_headers)}"
    )
    cache_control = head_headers.get("cache-control", "<absent>")
    assert "no-store" in cache_control.lower(), (
        f"RFC 8555 §7.2 requires Cache-Control: no-store on the newNonce response; got "
        f"{cache_control!r} -- a cached nonce is a replayable nonce"
    )

    # (6) GET newNonce: the RFC's other half -- an empty 204 that still carries a nonce.
    get_status, get_headers = _new_nonce(ctx, new_nonce_url, method="GET")
    assert get_status == 204, (
        f"RFC 8555 §7.2: GET {new_nonce_url!r} must answer 204 No Content; got {get_status}"
    )
    assert get_headers.get("replay-nonce", ""), (
        f"GET {new_nonce_url!r} must carry a Replay-Nonce header; headers were "
        f"{sorted(get_headers)}"
    )

    # (7) Terminal assertion, at the destination, through a repeated independent read: four
    #     successive fetches yield four DIFFERENT nonces. This is the inverse of a freeze
    #     detector -- a constant-nonce implementation is exactly what a cheap stub produces,
    #     and it is invisible to every control-plane assertion.
    nonces = [first_nonce, get_headers["replay-nonce"]]
    for _ in range(2):
        _status, more_headers = _new_nonce(ctx, new_nonce_url, method="HEAD")
        nonces.append(more_headers["replay-nonce"])
    assert len(set(nonces)) == len(nonces), (
        f"four successive newNonce fetches must yield four distinct nonces; got {nonces!r} "
        f"({len(set(nonces))} distinct)"
    )

    # (8) And the endpoint the AWS control plane describes is still the one that served all of
    #     the above -- read back through a different operation than the one that created it.
    described = _retry_throttle(
        lambda: acm.describe_acme_endpoint(AcmeEndpointArn=endpoint_arn))["AcmeEndpoint"]
    assert described["EndpointUrl"] == directory_url, (
        f"DescribeAcmeEndpoint now reports {described['EndpointUrl']!r} but the directory that "
        f"served this check was {directory_url!r}"
    )
    assert described["Status"] == "ACTIVE", (
        f"the endpoint must still be ACTIVE after serving its directory; Status is "
        f"{described['Status']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
