"""package-version-readme-unicode-round-trip."""
from __future__ import annotations

import base64
import hashlib
import io
import json
import ssl
import tarfile
import time
import urllib.error
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "package-version-readme-unicode-round-trip"
GROUP = "server-side"
SERVICES = ["codeartifact"]

README_TEXT = (
    "# sim2real \u6d4b\u8bd5\n\n"
    "\u3053\u306e\u30d1\u30f3\u30c9\u30fc\u30ab\u30c7\u30fc\u306f\u30c6\u30ad\u30b9\u30c8\u3067\u3059\u3002\n"
    "\u00dcn\u00efc\u00f6d\u00e9 \u2603\ufe0f \U0001f389 caf\u00e9, \u4e2d\u6587, \u0440\u0443\u0441\u0441\u043a\u0438\u0439.\n"
)


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A multi-byte unicode README in an npm package published through the repository's npm endpoint is
    returned identical by GetPackageVersionReadme."""
    ca = ctx.client("codeartifact")
    domain = ctx.unique_name("sim2real-careadme-")
    ca.create_domain(domain=domain, tags=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(lambda: ca.delete_domain(domain=domain))

    repo = ctx.unique_name("repo-")
    ca.create_repository(domain=domain, repository=repo, tags=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(lambda: ca.delete_repository(domain=domain, repository=repo))

    package = ctx.unique_name("npmreadme").replace("-", "")
    version = "1.0.0"
    tarball = _build_npm_tarball(package, version, README_TEXT)

    endpoint = ca.get_repository_endpoint(domain=domain, repository=repo, format="npm")[
        "repositoryEndpoint"
    ]
    token = ca.get_authorization_token(domain=domain)["authorizationToken"]
    _npm_publish(ctx, endpoint, package, version, tarball, README_TEXT, token)

    readme = _poll_for_readme(ca, domain, repo, package, version, timeout_s=90.0)
    assert readme == README_TEXT, f"readme mismatch: {readme!r} != {README_TEXT!r}"


def _build_npm_tarball(package_name: str, version: str, readme_text: str) -> bytes:
    buf = io.BytesIO()
    manifest = json.dumps(
        {
            "name": package_name,
            "version": version,
            "description": "sim2real fidelity check",
            "readme": readme_text,
        }
    ).encode("utf-8")
    readme_bytes = readme_text.encode("utf-8")
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for name, data in (
            ("package/package.json", manifest),
            ("package/README.md", readme_bytes),
        ):
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def _npm_publish(
    ctx,
    endpoint: str,
    package_name: str,
    version: str,
    tarball: bytes,
    readme_text: str,
    token: str,
) -> None:
    """Publish an npm package version using the npm registry PUT protocol, exactly
    as the real `npm publish` CLI does against a CodeArtifact npm repository
    endpoint (PublishPackageVersion itself only accepts the "generic" format).
    """
    tarball_name = f"{package_name}-{version}.tgz"
    shasum = hashlib.sha1(tarball).hexdigest()
    integrity = "sha512-" + base64.b64encode(hashlib.sha512(tarball).digest()).decode("ascii")
    body = {
        "_id": package_name,
        "name": package_name,
        "description": "sim2real fidelity check",
        "dist-tags": {"latest": version},
        "versions": {
            version: {
                "name": package_name,
                "version": version,
                "description": "sim2real fidelity check",
                "readme": readme_text,
                "_id": f"{package_name}@{version}",
                "dist": {
                    "tarball": f"{endpoint.rstrip('/')}/{package_name}/-/{tarball_name}",
                    "shasum": shasum,
                    "integrity": integrity,
                },
            }
        },
        "readme": readme_text,
        "_attachments": {
            tarball_name: {
                "content_type": "application/octet-stream",
                "data": base64.b64encode(tarball).decode("ascii"),
                "length": len(tarball),
            }
        },
    }
    payload = json.dumps(body).encode("utf-8")
    # The repository endpoint's host names the domain; the route headers carry it when the
    # target serves the repository at its own endpoint.
    url, route_headers = ctx.endpoint_route(endpoint.rstrip("/") + f"/{package_name}")
    req = urllib.request.Request(url, data=payload, method="PUT", headers=route_headers)
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=60, context=_ssl_context(ctx.http_verify)) as resp:
            resp.read()

    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise AssertionError(f"npm publish PUT failed ({exc.code}): {detail}") from exc


def _ssl_context(verify):
    """An SSLContext honouring ``ctx.http_verify``: True, False, or a CA bundle path."""
    if verify is False:
        return ssl._create_unverified_context()
    return ssl.create_default_context(cafile=verify if isinstance(verify, str) else None)


def _poll_for_readme(ca, domain, repo, package, version, timeout_s=90.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            resp = ca.get_package_version_readme(
                domain=domain,
                repository=repo,
                format="npm",
                package=package,
                packageVersion=version,
            )
            if resp.get("readme"):
                return resp["readme"]
        except ClientError as exc:
            last_exc = exc
        time.sleep(interval_s)
    raise AssertionError(f"readme was never populated: {last_exc}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

