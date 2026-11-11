"""repository-pull-count-counts-the-registry-v2-pulls."""
from __future__ import annotations

import hashlib
import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "repository-pull-count-counts-the-registry-v2-pulls"
GROUP = "metric-emission"
SERVICES = ["cloudwatch", "ecr"]

#: Non-round, and larger than any plausible off-by-one, so an emulator publishing "1" or "the number
#: of images" cannot land on it.
_N_PULLS = 6

_METRIC_BUDGET_S = 600.0
_ABSENCE_HOLD_S = 180.0

#: CloudWatch's StandardUnit enumeration. "Integer", which the ECR docs print, is deliberately NOT in
#: it, because it is not a CloudWatch StandardUnit.
_STANDARD_UNITS = frozenset(
    {
        "Seconds", "Microseconds", "Milliseconds",
        "Bytes", "Kilobytes", "Megabytes", "Gigabytes", "Terabytes",
        "Bits", "Kilobits", "Megabits", "Gigabits", "Terabits",
        "Percent", "Count",
        "Bytes/Second", "Kilobytes/Second", "Megabytes/Second", "Gigabytes/Second",
        "Terabytes/Second",
        "Bits/Second", "Kilobits/Second", "Megabits/Second", "Gigabits/Second",
        "Terabits/Second",
        "Count/Second", "None",
    }
)


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/AmazonECR/latest/userguide/ecr-repository-metrics.html
@tags(
    "axis:happy-path",
    "cap:c2",
    "concern:data-plane",
    "concern:metrics",
    "dp:endpoint",
    "plane:data", "timing:real-time",
)
def run(ctx) -> None:
    """Image pulls over the Docker Registry HTTP API v2 are counted exactly in AWS/ECR
    RepositoryPullCount under the RepositoryName dimension alone, with one standard Unit, while a
    twin repository pushed to the same way but never pulled publishes nothing."""
    ecr = ctx.client("ecr")
    cw = ctx.client("cloudwatch")

    pulled = _repository(ctx, ecr, "pulled-")
    # Same instant, same image, same layer count: differs ONLY in never being pulled from.
    never_pulled = _repository(ctx, ecr, "quiet-")

    pulled_digest = _push_minimal_image(ecr, pulled, "v1")
    _push_minimal_image(ecr, never_pulled, "v1")

    auth = ecr.get_authorization_token()["authorizationData"][0]
    proxy = auth["proxyEndpoint"].rstrip("/")
    token = auth["authorizationToken"]

    # ---- drive exactly _N_PULLS complete pulls over the real registry protocol ------------------ #
    for i in range(_N_PULLS):
        digest = _pull_image(ctx, proxy, token, pulled, "v1")
        assert digest == pulled_digest, (
            f"pull {i + 1} of {_N_PULLS} over /v2/{pulled}/manifests/v1 recomputed manifest "
            f"digest {digest!r} (ECR's manifest GET carries no Docker-Content-Digest header — "
            f"measured, not a client bug), expected the digest PutImage reported, "
            f"{pulled_digest!r}; the pull total asserted below is only attributable to pulls that "
            f"actually served the right image"
        )

    # ---- terminal read at CloudWatch ---------------------------------------------------------- #
    window_start = datetime.now(timezone.utc) - timedelta(minutes=25)

    def _dps(repo: str) -> list[dict]:
        return cw.get_metric_statistics(
            Namespace="AWS/ECR",
            MetricName="RepositoryPullCount",
            Dimensions=[{"Name": "RepositoryName", "Value": repo}],
            StartTime=window_start,
            EndTime=datetime.now(timezone.utc) + timedelta(minutes=5),
            Period=60,
            Statistics=["Sum", "SampleCount", "Maximum"],
        )["Datapoints"]

    def _sum(repo: str) -> float | None:
        dps = _dps(repo)
        return float(sum(d["Sum"] for d in dps)) if dps else None

    # Stability rather than "poll until >= N": counting per blob would be an OVER-count, which
    # a one-sided poll cannot detect because it stops at the first sufficient reading.
    total = _poll_until_stable(
        lambda: _sum(pulled),
        window_s=150.0,
        timeout_s=_METRIC_BUDGET_S,
        interval_s=15.0,
        description=(
            f"AWS/ECR RepositoryPullCount for RepositoryName={pulled} settling on one value "
            f"(ECR sends metric data in one-minute periods)"
        ),
    )
    assert total == float(_N_PULLS), (
        f"AWS/ECR RepositoryPullCount Sum for RepositoryName={pulled} settled at {total!r}, expected "
        f"{float(_N_PULLS)} — this check performed exactly {_N_PULLS} complete pulls (manifest, "
        f"config blob and layer blob each time) over the Docker Registry v2 endpoint. If the value "
        f"is a clean multiple of {_N_PULLS}, ECR is counting per blob rather than per pull and the "
        f"contract must be re-cut to that measured multiplier (see H3)"
    )

    dps = _dps(pulled)
    assert dps, f"AWS/ECR RepositoryPullCount vanished on re-read for {pulled}: {dps!r}"
    units = {d.get("Unit") for d in dps}
    assert len(units) == 1, (
        f"AWS/ECR RepositoryPullCount datapoints for {pulled} carry MIXED Unit(s) {units!r}; one "
        f"series must carry one unit"
    )
    unit = next(iter(units))
    assert unit in _STANDARD_UNITS, (
        f"AWS/ECR RepositoryPullCount for {pulled} reports Unit {unit!r}, which is not a member of "
        f"CloudWatch's StandardUnit enumeration. Note the ECR documentation prints 'Unit: Integer', "
        f"which is NOT a StandardUnit value — a target that echoes the documentation's word instead "
        f"of a real unit lands exactly here. The observed value must be recorded and pinned by a "
        f"later revision (see H2)"
    )

    sets = _dimension_sets(cw, "AWS/ECR", "RepositoryName", pulled)
    assert sets == {("RepositoryName",)}, (
        f"ListMetrics reports dimension sets {sorted(sets)!r} for the AWS/ECR series naming "
        f"RepositoryName={pulled}; ECR documents RepositoryName as the dimension that "
        f"\"filters the data that you request for all container images in a specified repository\", "
        f"so that must be the only set"
    )

    # ---- the structural control, held after the positive settled ------------------------------- #
    _assert_stays(
        lambda: _sum(never_pulled),
        None,
        hold_s=_ABSENCE_HOLD_S,
        interval_s=20.0,
        description=(
            f"the twin repository {never_pulled}, created in the same instant and pushed the same "
            f"image but never pulled from, publishes no AWS/ECR RepositoryPullCount datapoint"
        ),
    )

    # ---- positive control, after the negative ------------------------------------------------- #
    final = _sum(pulled)
    assert final == float(_N_PULLS), (
        f"after the twin's absence window RepositoryPullCount for {pulled} read {final!r}, expected "
        f"{float(_N_PULLS)} — the absence above is only meaningful while the positive series is served"
    )


def _repository(ctx, ecr, label: str) -> str:
    name = ctx.unique_name(f"sim2real-cwecr-{label}")
    ecr.create_repository(
        repositoryName=name,
        tags=[{"Key": "sim2real", "Value": "cloudwatch__ecr"}],
    )
    ctx.on_cleanup(lambda: ecr.delete_repository(repositoryName=name, force=True))
    return name


def _upload_blob(ecr, repo: str, data: bytes) -> str:
    digest = f"sha256:{hashlib.sha256(data).hexdigest()}"
    upload_id = ecr.initiate_layer_upload(repositoryName=repo)["uploadId"]
    ecr.upload_layer_part(
        repositoryName=repo,
        uploadId=upload_id,
        partFirstByte=0,
        partLastByte=len(data) - 1,
        layerPartBlob=data,
    )
    ecr.complete_layer_upload(
        repositoryName=repo, uploadId=upload_id, layerDigests=[digest]
    )
    return digest


def _push_minimal_image(ecr, repo: str, tag: str) -> str:
    """A schema-2 image with one config blob and one layer blob."""
    layer_bytes = b"sim2real-cwecr-layer-" + os.urandom(16)
    layer_digest = _upload_blob(ecr, repo, layer_bytes)
    config = {
        "architecture": "amd64",
        "os": "linux",
        "config": {},
        "rootfs": {"type": "layers", "diff_ids": [layer_digest]},
        "history": [{"created": "2024-01-01T00:00:00Z", "created_by": "sim2real"}],
    }
    config_bytes = json.dumps(config).encode("utf-8")
    config_digest = _upload_blob(ecr, repo, config_bytes)
    manifest = {
        "schemaVersion": 2,
        "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
        "config": {
            "mediaType": "application/vnd.docker.container.image.v1+json",
            "size": len(config_bytes),
            "digest": config_digest,
        },
        "layers": [
            {
                "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
                "size": len(layer_bytes),
                "digest": layer_digest,
            }
        ],
    }
    resp = ecr.put_image(
        repositoryName=repo,
        imageManifest=json.dumps(manifest),
        imageTag=tag,
    )
    return resp["image"]["imageId"]["imageDigest"]


class _StripAuthOnCrossOriginRedirect(urllib.request.HTTPRedirectHandler):
    """A blob GET is 307'd cross-origin to a presigned S3 URL that already carries its own auth
    in the query string; urllib's default redirect_request forwards every header but
    Content-Length/Content-Type, so the original ECR Basic-auth header rides along and S3
    answers 400 InvalidArgument ("Only one auth mechanism allowed"). A real registry client
    (`docker pull`) never resends the ECR credential to a different host, so this strips it the
    same way."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        new_req = super().redirect_request(req, fp, code, msg, headers, newurl)
        if new_req is not None and urllib.parse.urlparse(newurl).netloc != urllib.parse.urlparse(
            req.full_url
        ).netloc:
            new_req.remove_header("Authorization")
        return new_req


_OPENER = urllib.request.build_opener(_StripAuthOnCrossOriginRedirect)


def _get(ctx, url: str, token: str, accept: str | None = None) -> tuple[int, bytes, dict]:
    headers = {"Authorization": f"Basic {token}"}
    if accept:
        headers["Accept"] = accept
    target_url, route_headers = ctx.endpoint_route(url)
    req = urllib.request.Request(target_url, headers={**headers, **route_headers}, method="GET")
    try:
        with _OPENER.open(req, timeout=30) as resp:
            return resp.status, resp.read(), dict(resp.headers)
    except urllib.error.HTTPError as exc:
        raise AssertionError(
            f"Docker Registry v2 GET {url} failed: HTTP {exc.code} {exc.read()!r}"
        ) from exc
    except urllib.error.URLError as exc:
        raise AssertionError(f"the ECR registry endpoint was unreachable at {url}: {exc}") from exc


def _pull_image(ctx, proxy: str, token: str, repo: str, tag: str) -> str:
    """One COMPLETE pull: the manifest, then every blob it references. Returns the manifest's
    content digest, RECOMPUTED from the response bytes rather than read off a
    Docker-Content-Digest header: measured against real AWS (tag lookup, digest lookup, and
    every Accept negotiation the Docker Registry v2 spec offers), ECR's manifest GET never sends
    that header, while the response body is byte-identical to what PutImage was given and its
    SHA-256 is byte-identical to PutImage's reported imageDigest. That measured invariant is what
    this recomputes and the caller compares against."""
    status, body, headers = _get(ctx,
        f"{proxy}/v2/{repo}/manifests/{tag}",
        token,
        accept="application/vnd.docker.distribution.manifest.v2+json",
    )
    assert status == 200, f"manifest GET for {repo}:{tag} returned HTTP {status}"
    assert "Docker-Content-Digest" not in headers, (
        f"the manifest response for {repo}:{tag} now carries a Docker-Content-Digest header "
        f"({headers['Docker-Content-Digest']!r}) that measurement on this account never saw; ECR "
        f"has apparently started sending it, and the recomputed-digest path below should be "
        f"cross-checked against it rather than silently ignoring a header that now exists"
    )
    manifest = json.loads(body)
    for blob in [manifest["config"]] + list(manifest["layers"]):
        blob_status, blob_bytes, _ = _get(ctx,
            f"{proxy}/v2/{repo}/blobs/{blob['digest']}", token
        )
        assert blob_status == 200, (
            f"blob GET for {repo}@{blob['digest']} returned HTTP {blob_status}; a pull that does not "
            f"fetch its blobs is not a pull"
        )
        assert len(blob_bytes) == blob["size"], (
            f"blob {blob['digest']} in {repo} served {len(blob_bytes)} bytes, but the manifest "
            f"declares {blob['size']}"
        )
    return f"sha256:{hashlib.sha256(body).hexdigest()}"


def _dimension_sets(cw, namespace: str, dim_name: str, dim_value: str) -> set[tuple[str, ...]]:
    seen: set[tuple[str, ...]] = set()
    token = None
    while True:
        kwargs: dict = {
            "Namespace": namespace,
            "Dimensions": [{"Name": dim_name, "Value": dim_value}],
        }
        if token:
            kwargs["NextToken"] = token
        page = cw.list_metrics(**kwargs)
        for m in page["Metrics"]:
            seen.add(tuple(sorted(d["Name"] for d in m["Dimensions"])))
        token = page.get("NextToken")
        if not token:
            return seen


def _poll_until_stable(probe, *, window_s, timeout_s, interval_s=15.0, description="reading"):
    deadline = time.monotonic() + timeout_s
    anchor, anchor_t, last = None, 0.0, None
    while time.monotonic() < deadline:
        last = probe()
        now = time.monotonic()
        if last is None:
            anchor, anchor_t = None, 0.0
        elif last != anchor:
            anchor, anchor_t = last, now
        elif now - anchor_t >= window_s:
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"{description} never held one complete value for {window_s}s within {timeout_s}s; "
        f"last reading was {last!r}"
    )


def _assert_stays(probe, expected, *, hold_s, interval_s=20.0, description="reading"):
    deadline = time.monotonic() + hold_s
    while True:
        got = probe()
        assert got == expected, (
            f"{description}: read {got!r}, expected it to stay {expected!r} for the whole {hold_s}s"
        )
        if time.monotonic() >= deadline:
            return
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
