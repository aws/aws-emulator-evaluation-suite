"""e2e-package-association-search-flow."""
from __future__ import annotations

import http.client
import json
import time
import urllib.error
import urllib.request

from behavioral_harness import tags
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest

CHECK = "e2e-package-association-search-flow"
GROUP = "e2e"
SERVICES = ["opensearch"]

# Stopwords the TXT-DICTIONARY package contains; only a field whose analyzer loads the package
# may drop them, which proves the association mounted real content.
_STOPWORD_1 = "sim2realstopword1"
_STOPWORD_2 = "sim2realstopword2"
_KEEP_WORD = "keepme"


@tags(
    "axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:e2e",
    "concern:representation", "dp:endpoint", "plane:control", "plane:data",
)
def run(ctx) -> None:
    """An associated TXT-DICTIONARY package is listed for the domain and its stopwords drive search
    through stopwords_path, unlike a standard-analyzer control field; dissociation unlists it.
    """
    osc = ctx.client("opensearch")
    s3 = ctx.client("s3")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    domain_name = ctx.unique_name("sim2real-pkg-")[:28].rstrip("-") or "sim2real-pkg-fallback"
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "es:*",
                "Resource": f"arn:aws:es:{ctx.region}:{account_id}:domain/{domain_name}/*",
            }
        ],
    }
    osc.create_domain(
        DomainName=domain_name,
        EngineVersion="OpenSearch_2.11",
        ClusterConfig={
            "InstanceType": "t3.small.search",
            "InstanceCount": 1,
            "DedicatedMasterEnabled": False,
            "ZoneAwarenessEnabled": False,
        },
        EBSOptions={"EBSEnabled": True, "VolumeType": "gp3", "VolumeSize": 10},
        AccessPolicies=json.dumps(policy),
        TagList=[{"Key": "sim2real", "Value": "e2e-package-association-search-flow"}],
    )
    ctx.on_cleanup(lambda: _delete_domain_quiet(osc, domain_name))
    domain_status = _wait_domain_active(osc, domain_name, timeout_s=1800)
    base = ctx.endpoint_url(domain_status["Endpoint"])
    _wait_data_plane_ready(ctx, base)

    bucket = ctx.unique_name("sim2real-ospkg-").lower()
    if ctx.region != "us-east-1":
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    else:
        s3.create_bucket(Bucket=bucket)
    ctx.on_cleanup(lambda: _delete_bucket_quiet(s3, bucket))
    key = "dictionaries/sim2real-custom-dictionary.txt"
    s3.put_object(Bucket=bucket, Key=key, Body=f"{_STOPWORD_1}\n{_STOPWORD_2}\n".encode())

    package_name = ctx.unique_name("sim2real-pkg-")[:250]
    pkg = osc.create_package(
        PackageName=package_name,
        PackageType="TXT-DICTIONARY",
        PackageSource={"S3BucketName": bucket, "S3Key": key},
    )["PackageDetails"]
    package_id = pkg["PackageID"]
    ctx.on_cleanup(lambda: _delete_package_quiet(osc, package_id))

    _wait_package_available(osc, package_id, timeout_s=900)

    osc.associate_package(PackageID=package_id, DomainName=domain_name)
    _wait_domain_package_status(osc, domain_name, package_id, "ACTIVE", timeout_s=600)

    listed = osc.list_packages_for_domain(DomainName=domain_name)["DomainPackageDetailsList"]
    assert any(p["PackageID"] == package_id for p in listed), listed

    index = ctx.unique_name("sim2real-pkg-idx-").lower()
    ctx.on_cleanup(lambda: _delete_index(ctx, base, index))
    _assert_package_content_drives_search(ctx, base, index, package_id)
    _delete_index(ctx, base, index)

    osc.dissociate_package(PackageID=package_id, DomainName=domain_name)
    _wait_package_absent_from_domain(osc, domain_name, package_id, timeout_s=600)


def _assert_package_content_drives_search(ctx, base, index, package_id) -> None:
    """The associated package's file, mounted at analyzers/<PackageID>, is loaded by a stop
    filter's ``stopwords_path`` -- so a field using that analyzer drops the package's stopwords
    from search while an identical control field (standard analyzer, same document) keeps them.
    """
    status, created = _signed_request(ctx, "PUT", f"{base}/{index}", body={
        "settings": {
            "index": {"number_of_shards": 1, "number_of_replicas": 0},
            "analysis": {
                "filter": {"pkg_stop": {"type": "stop", "stopwords_path": f"analyzers/{package_id}"}},
                "analyzer": {"pkg_analyzer": {
                    "type": "custom", "tokenizer": "standard", "filter": ["lowercase", "pkg_stop"],
                }},
            },
        },
        "mappings": {"properties": {
            "pkg_text": {"type": "text", "analyzer": "pkg_analyzer"},
            "plain_text": {"type": "text", "analyzer": "standard"},
        }},
    })
    assert status == 200, f"creating index {index!r} returned HTTP {status!r}: {created!r}"

    doc_text = f"{_STOPWORD_1} {_KEEP_WORD} {_STOPWORD_2}"
    status, indexed = _signed_request(ctx, "PUT", f"{base}/{index}/_doc/1",
                                      body={"pkg_text": doc_text, "plain_text": doc_text})
    assert status == 201, f"indexing the document returned HTTP {status!r}: {indexed!r}"
    status, _ = _signed_request(ctx, "POST", f"{base}/{index}/_refresh")
    assert status == 200, f"_refresh returned HTTP {status!r}"

    def _hits(field: str, term: str) -> int:
        status, body = _signed_request(ctx, "POST", f"{base}/{index}/_search",
                                       body={"query": {"match": {field: term}}})
        assert status == 200, f"the match query on {field!r} for {term!r} returned HTTP {status!r}: {body!r}"
        total = body.get("hits", {}).get("total")
        return total.get("value") if isinstance(total, dict) else total

    assert _hits("pkg_text", _KEEP_WORD) == 1, (
        f"a non-stopword term must still be found through the package-driven field"
    )
    assert _hits("pkg_text", _STOPWORD_1) == 0, (
        f"the package's own stopword {_STOPWORD_1!r} must be dropped from the field whose analyzer "
        f"loads the associated package via stopwords_path=analyzers/{package_id} -- a hit here means "
        f"the association mounted no usable content"
    )
    assert _hits("plain_text", _STOPWORD_1) == 1, (
        f"the identical text on the standard-analyzed control field must still contain "
        f"{_STOPWORD_1!r} -- this is what makes the package-driven field's zero hits above "
        f"attributable to the package's content rather than to a failed write"
    )


# ===== shared domain helpers =====
def _signed_request(ctx, method, url, *, body=None, content_type="application/json"):
    """SigV4-signed ('es') HTTPS request to a domain endpoint -> (status, parsed_json).

    Signs with the credentials of ctx's clients, not boto3's ambient chain.
    """
    signer_creds = ctx.client("opensearch")._request_signer._credentials
    if signer_creds is None:
        raise AssertionError("no AWS credentials available to sign OpenSearch data-plane requests")
    frozen = signer_creds.get_frozen_credentials()
    data = json.dumps(body).encode() if body is not None else None
    headers = {"Content-Type": content_type} if data is not None else {}
    aws_req = AWSRequest(method=method, url=url, data=data, headers=headers)
    SigV4Auth(frozen, "es", ctx.region).add_auth(aws_req)
    req = urllib.request.Request(url, data=data, method=method, headers=dict(aws_req.headers))
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            text = resp.read().decode()
            return resp.status, (json.loads(text) if text else {})
    except urllib.error.HTTPError as exc:
        text = exc.read().decode(errors="replace")
        try:
            return exc.code, json.loads(text)
        except ValueError:
            return exc.code, {"raw": text}
    except (OSError, http.client.HTTPException) as exc:  # the endpoint did not answer at all
        raise AssertionError(
            f"DATAPLANE_UNIMPLEMENTED: signed {method} to the domain endpoint did not complete: "
            f"{type(exc).__name__}: {exc}"
        ) from exc


def _wait_data_plane_ready(ctx, base, timeout_s=300.0):
    """Processing=False + a published Endpoint does NOT mean the data-plane authorizer has the
    access policy yet; signed requests can 403 for a while. Poll a cheap GET until it clears.
    """
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status, _ = _signed_request(ctx, "GET", f"{base}/")
        if status != 403:
            return
        time.sleep(2)
    raise AssertionError(f"domain data plane still answered 403 after {timeout_s}s (last status {status})")


def _delete_index(ctx, base, index) -> None:
    """Delete the index; AWS requires this before the package it references can be dissociated."""
    status, body = _signed_request(ctx, "DELETE", f"{base}/{index}")
    assert status in (200, 404), f"deleting index {index!r} returned HTTP {status!r}: {body!r}"


def _wait_domain_active(osc, domain_name, timeout_s=1800.0, interval_s=30.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = osc.describe_domain(DomainName=domain_name)["DomainStatus"]
        if last["Processing"] is False and last.get("Endpoint"):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"domain {domain_name} never became Active within {timeout_s}s: {last}")


def _wait_package_available(osc, package_id, timeout_s=900.0, interval_s=15.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        resp = osc.describe_packages(
            Filters=[{"Name": "PackageID", "Value": [package_id]}]
        )["PackageDetailsList"]
        last = resp[0]["PackageStatus"] if resp else None
        if last == "AVAILABLE":
            return
        if last in ("COPY_FAILED", "VALIDATION_FAILED"):
            raise AssertionError(f"package {package_id} failed to become available: {last}")
        time.sleep(interval_s)
    raise AssertionError(f"package {package_id} never became AVAILABLE within {timeout_s}s: {last}")


def _wait_domain_package_status(osc, domain_name, package_id, target, timeout_s=600.0, interval_s=15.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        listed = osc.list_packages_for_domain(DomainName=domain_name)["DomainPackageDetailsList"]
        entry = next((p for p in listed if p["PackageID"] == package_id), None)
        last = entry["DomainPackageStatus"] if entry else None
        if last == target:
            return
        if last == "ASSOCIATION_FAILED":
            raise AssertionError(f"package {package_id} association failed")
        time.sleep(interval_s)
    raise AssertionError(f"package {package_id} never reached {target} on domain: last={last}")


def _wait_package_absent_from_domain(osc, domain_name, package_id, timeout_s=600.0, interval_s=15.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        listed = osc.list_packages_for_domain(DomainName=domain_name)["DomainPackageDetailsList"]
        if not any(p["PackageID"] == package_id for p in listed):
            return
        time.sleep(interval_s)
    raise AssertionError(f"package {package_id} still listed on domain {domain_name} after dissociate")


def _delete_domain_quiet(osc, domain_name):
    try:
        osc.delete_domain(DomainName=domain_name)
    except Exception as exc:  # noqa: BLE001
        if _error_code_from_exc(exc) != "ResourceNotFoundException":
            raise


def _delete_package_quiet(osc, package_id):
    try:
        osc.delete_package(PackageID=package_id)
    except Exception as exc:  # noqa: BLE001
        if _error_code_from_exc(exc) not in ("ResourceNotFoundException", "ConflictException"):
            raise


def _delete_bucket_quiet(s3, bucket):
    try:
        resp = s3.list_objects_v2(Bucket=bucket)
        for obj in resp.get("Contents", []):
            s3.delete_object(Bucket=bucket, Key=obj["Key"])
        s3.delete_bucket(Bucket=bucket)
    except Exception as exc:  # noqa: BLE001
        if _error_code_from_exc(exc) not in ("NoSuchBucket",):
            raise


def _error_code_from_exc(exc):
    resp = getattr(exc, "response", None)
    if not resp:
        return None
    return resp.get("Error", {}).get("Code")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
