"""list-package-version-dependencies-preserves-declared-order."""
from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from pathlib import Path
from urllib.parse import urlparse

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "list-package-version-dependencies-preserves-declared-order"
GROUP = "ordering"
SERVICES = ["codeartifact"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """ListPackageVersionDependencies returns dependencies in the order the published npm
    manifest's "dependencies" object declared them.
    """
    require_tools("npm")
    npm = shutil.which("npm")

    ca = ctx.client("codeartifact")
    domain = ctx.unique_name("sim2real-behav-ca-")
    ca.create_domain(domain=domain, tags=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(lambda: ca.delete_domain(domain=domain))
    repo = ctx.unique_name("sim2real-behav-repo-")
    ca.create_repository(domain=domain, repository=repo, tags=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(lambda: ca.delete_repository(domain=domain, repository=repo))

    token = ca.get_authorization_token(domain=domain)["authorizationToken"]
    endpoint = ctx.endpoint_url(
        ca.get_repository_endpoint(domain=domain, repository=repo, format="npm")["repositoryEndpoint"]
    )

    package = ctx.unique_name("sim2real-behav-pkg-").lower().replace("_", "-")
    version = "1.0.0"
    # Deliberately non-alphabetical order to make the assertion meaningful.
    declared_order = ["zeta-dep", "alpha-dep", "mid-dep"]

    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        npmrc = tmp_path / ".npmrc"
        npmrc.write_text(_npmrc_contents(endpoint, token))
        pkg_dir = tmp_path / "pkg"
        pkg_dir.mkdir()
        package_json = {
            "name": package,
            "version": version,
            "description": "sim2real behavioral fidelity check package",
            "dependencies": {dep: "^1.0.0" for dep in declared_order},
        }
        (pkg_dir / "package.json").write_text(json.dumps(package_json, indent=2))
        (pkg_dir / "index.js").write_text("module.exports = {};\n")

        env = dict(ctx.subprocess_env())
        env["NPM_CONFIG_USERCONFIG"] = str(npmrc)
        env["npm_config_userconfig"] = str(npmrc)

        # PublishPackageVersion only takes generic assets, which carry no dependency manifest,
        # so the package is published over the npm registry protocol with the npm CLI.
        result = subprocess.run(
            [npm, "publish", "--registry", endpoint],
            cwd=str(pkg_dir),
            env=env,
            capture_output=True,
            text=True,
            timeout=120,
        )
        if result.returncode != 0:
            raise AssertionError(
                f"npm publish failed (rc={result.returncode}):\n"
                f"stdout={result.stdout}\nstderr={result.stderr}"
            )

    resp = ca.list_package_version_dependencies(
        domain=domain,
        repository=repo,
        format="npm",
        package=package,
        packageVersion=version,
    )
    observed_order = [dep["package"] for dep in resp["dependencies"]]
    assert observed_order == declared_order, (
        f"expected dependency order {declared_order}, got {observed_order}"
    )


def _npmrc_contents(endpoint: str, token: str) -> str:
    parsed = urlparse(endpoint)
    host_path = parsed.netloc + parsed.path
    if not host_path.endswith("/"):
        host_path += "/"
    return (
        f"registry={endpoint}\n"
        f"//{host_path}:_authToken={token}\n"
        f"//{host_path}:always-auth=true\n"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
