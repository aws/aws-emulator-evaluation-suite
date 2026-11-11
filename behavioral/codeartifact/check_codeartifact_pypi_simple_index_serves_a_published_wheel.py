"""codeartifact-pypi-simple-index-serves-a-published-wheel."""
from __future__ import annotations

import base64
import hashlib
import io
import re
import urllib.error
import urllib.parse
import urllib.request
import uuid
import zipfile

from behavioral_harness import tags


def _routed_request(ctx, url, data=None, headers=None, **kwargs):
    """A urllib Request that reaches ``url`` on the target, with ``ctx.endpoint_route``'s headers."""
    target, route = ctx.endpoint_route(url)
    return urllib.request.Request(target, data=data, headers={**(headers or {}), **route}, **kwargs)


CHECK = "codeartifact-pypi-simple-index-serves-a-published-wheel"
GROUP = 'package-endpoint'
SERVICES = ['codeartifact']


@tags("axis:happy-path", "concern:data-plane", "dp:endpoint", "plane:data", "cap:c1")
def run(ctx) -> None:
    """A wheel uploaded to the repository endpoint is listed once, with its sha256, in the PEP 503
    index under the normalized project name and downloads back byte-identically, matching the asset
    ListPackageVersionAssets reports."""
    ca = ctx.client("codeartifact")
    domain = ctx.unique_name("sim2real-ca-")
    repository = ctx.unique_name("sim2real-repo-")

    ca.create_domain(domain=domain, tags=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(lambda: ca.delete_domain(domain=domain))
    ca.create_repository(domain=domain, repository=repository,
                         tags=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(lambda: ca.delete_repository(domain=domain, repository=repository))

    token = ca.get_authorization_token(domain=domain,
                                       durationSeconds=900)["authorizationToken"]
    endpoint = ca.get_repository_endpoint(domain=domain, repository=repository,
                                          format="pypi")["repositoryEndpoint"]
    basic = "Basic " + base64.b64encode(f"aws:{token}".encode()).decode()

    # A distribution name with an underscore, so PEP 503 normalisation is observable: the
    # wheel filename keeps the underscore, the index path must use the hyphen form.
    distribution = ctx.unique_name("sim2real_whl_").replace("-", "_")
    normalized = re.sub(r"[-_.]+", "-", distribution).lower()
    assert "_" in distribution and "_" not in normalized, (
        f"the fixture name {distribution!r} does not exercise normalisation "
        f"(normalized to {normalized!r})"
    )
    payload = b"sim2real wheel payload: the exact bytes pip must receive\n"
    wheel_name, wheel_bytes = _wheel(distribution, "1.0.0", payload)
    sha256 = hashlib.sha256(wheel_bytes).hexdigest()

    content_type, body = _multipart([
        (":action", "file_upload"), ("protocol_version", "1"), ("metadata_version", "2.1"),
        ("name", normalized), ("version", "1.0.0"), ("filetype", "bdist_wheel"),
        ("pyversion", "py3"), ("summary", "sim2real fidelity fixture"),
        ("sha256_digest", sha256), ("md5_digest", hashlib.md5(wheel_bytes).hexdigest()),
    ], wheel_name, wheel_bytes)
    up_status, up_body = _http(ctx, endpoint, method="POST", basic=basic, body=body,
                               content_type=content_type)
    assert up_status == 201, f"pypi upload returned {up_status!r}: {up_body[:400]!r}"

    idx_status, idx_body = _http(ctx, endpoint + f"simple/{normalized}/", basic=basic)
    assert idx_status == 200, (
        f"the PEP 503 index for {normalized!r} returned {idx_status!r}: {idx_body[:400]!r}"
    )
    index_html = idx_body.decode()
    hrefs = re.findall(r'href="([^"]+)"', index_html)
    assert [h.split("#", 1)[0].rsplit("/", 1)[-1] for h in hrefs] == [wheel_name], (
        f"the simple index listed {hrefs!r}, expected exactly one link to {wheel_name!r}"
    )
    assert f"sha256={sha256}" in hrefs[0], (
        f"the index href did not pin the wheel's sha256 {sha256!r}: {hrefs[0]!r}"
    )
    assert f"Links for {normalized}" in index_html, (
        f"PEP 503 normalisation was not applied — {normalized!r} absent from {index_html[:300]!r}"
    )

    dl_status, downloaded = _http(ctx, urllib.parse.urljoin(endpoint + f"simple/{normalized}/",
                                                       hrefs[0]), basic=basic)
    assert dl_status == 200, f"the advertised href returned {dl_status!r}: {downloaded[:300]!r}"
    assert downloaded == wheel_bytes, (
        f"the endpoint served {len(downloaded)!r} bytes (sha256 "
        f"{hashlib.sha256(downloaded).hexdigest()!r}) for a {len(wheel_bytes)!r}-byte upload "
        f"(sha256 {sha256!r})"
    )
    with zipfile.ZipFile(io.BytesIO(downloaded)) as zf:
        served = zf.read(f"{distribution}/__init__.py")
    assert served == payload, f"the file inside the served wheel is {served!r}, uploaded {payload!r}"

    assets = _paginate(ca.list_package_version_assets, "assets", domain=domain,
                      repository=repository, format="pypi", package=normalized,
                      packageVersion="1.0.0")
    assert {a["name"] for a in assets} == {wheel_name}, (
        f"ListPackageVersionAssets reported {[a['name'] for a in assets]!r}, but the index "
        f"served {wheel_name!r}"
    )
    assert assets[0]["hashes"]["SHA-256"] == sha256, (
        f"the recorded SHA-256 {assets[0]['hashes']['SHA-256']!r} disagrees with the uploaded "
        f"bytes {sha256!r}"
    )


def _http(ctx, url: str, *, method: str = "GET", basic: str | None = None, body: bytes | None = None,
          content_type: str | None = None, timeout_s: float = 60.0) -> tuple[int, bytes]:
    """One package-manager-protocol exchange, returning (status, body) for any HTTP status."""
    headers = {"Authorization": basic} if basic else {}
    if content_type:
        headers["Content-Type"] = content_type
    req = _routed_request(ctx, url, method=method, data=body, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:  # noqa: S310
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


def _wheel(distribution: str, version: str, payload: bytes) -> tuple[str, bytes]:
    """A minimal but valid py3-none-any wheel: METADATA, WHEEL, RECORD and one payload file."""
    dist_info = f"{distribution}-{version}.dist-info"
    files = {
        f"{distribution}/__init__.py": payload,
        f"{dist_info}/METADATA": (f"Metadata-Version: 2.1\nName: {distribution}\n"
                                  f"Version: {version}\nSummary: sim2real fidelity fixture\n"
                                  ).encode(),
        f"{dist_info}/WHEEL": (b"Wheel-Version: 1.0\nGenerator: sim2real\n"
                               b"Root-Is-Purelib: true\nTag: py3-none-any\n"),
    }
    record = "".join(
        f"{name},sha256="
        f"{base64.urlsafe_b64encode(hashlib.sha256(data).digest()).decode().rstrip('=')},"
        f"{len(data)}\n" for name, data in files.items()) + f"{dist_info}/RECORD,,\n"
    files[f"{dist_info}/RECORD"] = record.encode()
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name in sorted(files):
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.external_attr = 0o644 << 16
            zf.writestr(info, files[name])
    return f"{distribution}-{version}-py3-none-any.whl", buf.getvalue()


def _multipart(fields: list[tuple[str, str]], filename: str,
               content: bytes) -> tuple[str, bytes]:
    """The multipart/form-data body twine POSTs for `:action=file_upload`."""
    boundary = "----sim2real" + uuid.uuid4().hex
    out = io.BytesIO()
    for key, value in fields:
        out.write(f"--{boundary}\r\nContent-Disposition: form-data; name=\"{key}\"\r\n"
                  f"\r\n{value}\r\n".encode())
    out.write(f"--{boundary}\r\nContent-Disposition: form-data; name=\"content\"; "
              f"filename=\"{filename}\"\r\n"
              "Content-Type: application/octet-stream\r\n\r\n".encode())
    out.write(content)
    out.write(f"\r\n--{boundary}--\r\n".encode())
    return f"multipart/form-data; boundary={boundary}", out.getvalue()


def _paginate(operation, key: str, **kwargs) -> list[dict]:
    """Every page of a CodeArtifact List* call."""
    out, next_token = [], None
    while True:
        page = operation(**kwargs, **({"nextToken": next_token} if next_token else {}))
        out.extend(page.get(key, []))
        next_token = page.get("nextToken")
        if not next_token:
            return out


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
