"""package-version-status-transitions-enforced-forward-only."""
from __future__ import annotations

import hashlib

from behavioral_harness import tags

CHECK = "package-version-status-transitions-enforced-forward-only"
GROUP = "ordering"
SERVICES = ["codeartifact"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Disposed is terminal: UpdatePackageVersionsStatus cannot move a Disposed version back to
    Published, while a legitimate forward transition among the other statuses still succeeds.
    """
    ca = ctx.client("codeartifact")
    resource_tags = [{"key": "sim2real", "value": CHECK}]
    domain = ctx.unique_name("sim2real-behav-ca-")
    ca.create_domain(domain=domain, tags=resource_tags)
    ctx.on_cleanup(lambda: ca.delete_domain(domain=domain))
    repo = ctx.unique_name("sim2real-behav-repo-")
    ca.create_repository(domain=domain, repository=repo, tags=resource_tags)
    ctx.on_cleanup(lambda: ca.delete_repository(domain=domain, repository=repo))
    package = ctx.unique_name("sim2real-behav-pkg-")

    # --- terminal-state negative: Disposed can never move back ---
    terminal_version = "1.0.0"
    namespace = "sim2real-behav-ns"
    _publish_generic(ctx, domain, repo, package, terminal_version)
    published_status = _status(ca, domain, repo, package, terminal_version)
    assert published_status == "Published", (
        f"freshly published {terminal_version!r} read status {published_status!r}, expected Published"
    )

    archive_resp = ca.update_package_versions_status(
        domain=domain,
        repository=repo,
        format="generic",
        namespace=namespace,
        package=package,
        versions=[terminal_version],
        targetStatus="Archived",
    )
    archived_status = archive_resp["successfulVersions"][terminal_version]["status"]
    assert archived_status == "Archived", (
        f"the Published->Archived transition reported status {archived_status!r}, expected Archived"
    )
    read_after_archive = _status(ca, domain, repo, package, terminal_version)
    assert read_after_archive == "Archived", (
        f"after the Archived transition a read returned status {read_after_archive!r}, expected Archived"
    )

    dispose_resp = ca.dispose_package_versions(
        domain=domain,
        repository=repo,
        format="generic",
        namespace=namespace,
        package=package,
        versions=[terminal_version],
    )
    disposed_status = dispose_resp["successfulVersions"][terminal_version]["status"]
    assert disposed_status == "Disposed", (
        f"disposing {terminal_version!r} reported status {disposed_status!r}, expected Disposed"
    )
    read_after_dispose = _status(ca, domain, repo, package, terminal_version)
    assert read_after_dispose == "Disposed", (
        f"after disposal a read returned status {read_after_dispose!r}, expected Disposed"
    )

    # expectedStatus cannot name Disposed (reachable only via DisposePackageVersions), so
    # the move back to Published is attempted without a guard.
    regress_resp = ca.update_package_versions_status(
        domain=domain,
        repository=repo,
        format="generic",
        namespace=namespace,
        package=package,
        versions=[terminal_version],
        targetStatus="Published",
    )
    assert terminal_version not in regress_resp.get("successfulVersions", {}), (
        f"moving a Disposed version back to Published reported successes "
        f"{regress_resp.get('successfulVersions', {})!r}; Disposed must be absorbing"
    )
    failed = regress_resp["failedVersions"][terminal_version]
    assert failed["errorCode"] == "NOT_ALLOWED", (
        f"the refusal's errorCode was {failed['errorCode']!r}, expected NOT_ALLOWED"
    )
    # The effect must be absent: status did not move.
    read_after_refusal = _status(ca, domain, repo, package, terminal_version)
    assert read_after_refusal == "Disposed", (
        f"the refused Disposed->Published transition left status {read_after_refusal!r}, "
        f"expected it to stay Disposed"
    )

    # --- positive control: a legitimate forward transition still works ---
    control_version = "1.0.1"
    _publish_generic(ctx, domain, repo, package, control_version)
    unlist_resp = ca.update_package_versions_status(
        domain=domain,
        repository=repo,
        format="generic",
        namespace=namespace,
        package=package,
        versions=[control_version],
        targetStatus="Unlisted",
    )
    unlisted_status = unlist_resp["successfulVersions"][control_version]["status"]
    assert unlisted_status == "Unlisted", (
        f"the control Published->Unlisted transition reported status {unlisted_status!r}, "
        f"expected Unlisted"
    )
    read_control = _status(ca, domain, repo, package, control_version)
    assert read_control == "Unlisted", (
        f"after the control transition a read returned status {read_control!r}, expected Unlisted"
    )


def _publish_generic(ctx, domain: str, repository: str, package: str, version: str) -> None:
    ca = ctx.client("codeartifact")
    content = f"sim2real behavioral asset for {package}@{version}".encode()
    sha256 = hashlib.sha256(content).hexdigest()
    ca.publish_package_version(
        domain=domain,
        repository=repository,
        format="generic",
        namespace="sim2real-behav-ns",
        package=package,
        packageVersion=version,
        assetContent=content,
        assetName="asset.txt",
        assetSHA256=sha256,
    )


def _status(ca, domain: str, repository: str, package: str, version: str) -> str:
    resp = ca.describe_package_version(
        domain=domain,
        repository=repository,
        format="generic",
        namespace="sim2real-behav-ns",
        package=package,
        packageVersion=version,
    )
    return resp["packageVersion"]["status"]



if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
