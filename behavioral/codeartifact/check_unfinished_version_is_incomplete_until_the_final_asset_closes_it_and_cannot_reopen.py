"""unfinished-version-is-incomplete-until-the-final-asset-closes-it-and-cannot-reopen."""

from __future__ import annotations

import hashlib
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "unfinished-version-is-incomplete-until-the-final-asset-closes-it-and-cannot-reopen"
GROUP = "package-version-status"
SERVICES = ["codeartifact"]

_NAMESPACE = "sim2real"
_ASSETS = {
    "first.bin": b"sim2real unfinished asset one\x00\xff\r\n",
    "second.bin": b"sim2real unfinished asset two",
    "closing.bin": b"sim2real closing asset, published without the unfinished flag\n",
}


@tags("axis:happy-path", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """A multi-asset generic version stays Unfinished until the final asset omits the flag, keeps
    every asset, and once Published cannot be set back to Unfinished.

    Reference: https://docs.aws.amazon.com/codeartifact/latest/APIReference/API_PublishPackageVersion.html
    """
    ca = ctx.client("codeartifact")
    domain = ctx.unique_name("sim2real-ca-dom-")
    repository = ctx.unique_name("sim2real-ca-repo-")

    ca.create_domain(domain=domain, tags=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(lambda: _delete_domain(ca, domain))
    ca.create_repository(domain=domain, repository=repository,
                         tags=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(lambda: _delete_repository(ca, domain, repository))

    package = ctx.unique_name("sim2real-unfinished-")
    scope = dict(format="generic", namespace=_NAMESPACE, package=package)
    ctx.on_cleanup(lambda: _delete_package(ca, domain, repository, package))

    # ---- the first two assets go up unfinished ---------------------------------------------
    for name in ("first.bin", "second.bin"):
        reported = ca.publish_package_version(
            domain=domain, repository=repository, packageVersion="1.0.0",
            assetContent=_ASSETS[name], assetName=name,
            assetSHA256=hashlib.sha256(_ASSETS[name]).hexdigest(), unfinished=True, **scope)
        assert reported["status"] == "Unfinished", (
            f"publishing {name!r} with unfinished=True left the version {reported['status']!r}; "
            f"expected 'Unfinished' until the final asset omits the flag"
        )
        independent = _status(ca, domain, repository, "1.0.0", **scope)
        assert independent == "Unfinished", (
            f"DescribePackageVersion reports {independent!r} after publishing {name!r} with "
            f"unfinished=True, but PublishPackageVersion reported "
            f"{reported['status']!r} — the two must agree"
        )

    # Both assets are already stored, even though the version is not finished.
    interim = _asset_names(ca, domain, repository, "1.0.0", **scope)
    assert interim == {"first.bin", "second.bin"}, (
        f"an unfinished version holds assets {sorted(interim)!r}, expected both uploaded assets "
        f"{sorted(('first.bin', 'second.bin'))!r} — unfinished means incomplete, not empty"
    )

    # The status filter partitions correctly while the version is unfinished.
    unfinished_slice = _versions(ca, domain, repository, status="Unfinished", **scope)
    assert unfinished_slice == {"1.0.0"}, (
        f"ListPackageVersions(status='Unfinished') returned {sorted(unfinished_slice)!r}, expected "
        f"exactly ['1.0.0']"
    )
    published_slice = _versions(ca, domain, repository, status="Published", **scope)
    assert published_slice == set(), (
        f"ListPackageVersions(status='Published') returned {sorted(published_slice)!r} while the "
        f"only version is Unfinished; expected nothing"
    )

    # Reading an unfinished version must not finish it.
    for probe in range(3):
        frozen = _status(ca, domain, repository, "1.0.0", **scope)
        assert frozen == "Unfinished", (
            f"read {probe + 1} of 3 reports {frozen!r}; three consecutive reads of an unfinished "
            f"version must all return 'Unfinished' — a read must not advance the state machine"
        )

    # ---- the closing asset omits the flag and finishes the version -------------------------
    closed = ca.publish_package_version(
        domain=domain, repository=repository, packageVersion="1.0.0",
        assetContent=_ASSETS["closing.bin"], assetName="closing.bin",
        assetSHA256=hashlib.sha256(_ASSETS["closing.bin"]).hexdigest(), **scope)
    assert closed["status"] == "Published", (
        f"the closing publish (no unfinished flag) left the version {closed['status']!r}, expected "
        f"'Published'"
    )
    described = ca.describe_package_version(
        domain=domain, repository=repository, packageVersion="1.0.0", **scope)["packageVersion"]
    assert described["status"] == "Published", (
        f"DescribePackageVersion reports {described['status']!r} after the closing publish, "
        f"expected 'Published'"
    )
    assert described["revision"] == closed["versionRevision"], (
        f"the closing publish reported revision {closed['versionRevision']!r} but "
        f"DescribePackageVersion returns {described['revision']!r}"
    )

    # Every asset from every publish survived, byte for byte.
    final_assets = _asset_names(ca, domain, repository, "1.0.0", **scope)
    assert final_assets == set(_ASSETS), (
        f"the finished version holds assets {sorted(final_assets)!r}, expected all three "
        f"{sorted(_ASSETS)!r} — closing a version must not discard the assets it was built from"
    )
    for name, content in _ASSETS.items():
        served = ca.get_package_version_asset(
            domain=domain, repository=repository, packageVersion="1.0.0", asset=name,
            **scope)["asset"].read()
        assert served == content, (
            f"asset {name!r} serves {len(served)} bytes (sha256 "
            f"{hashlib.sha256(served).hexdigest()!r}); it was published as {len(content)} bytes "
            f"(sha256 {hashlib.sha256(content).hexdigest()!r})"
        )

    # ---- Published cannot be reopened as Unfinished ---------------------------------------
    # The refusal may be a top-level exception or a failedVersions entry, so assert only that
    # the call did not succeed and an independent read still says Published.
    reopen = _attempted_status_change(
        ca, domain, repository, package, "1.0.0", target="Unfinished", expected="Published")
    assert reopen["succeeded"] is False, (
        f"UpdatePackageVersionsStatus(targetStatus='Unfinished') on a Published version "
        f"{reopen!r}; once Published a version cannot change back to Unfinished"
    )
    after_reopen = _status(ca, domain, repository, "1.0.0", **scope)
    assert after_reopen == "Published", (
        f"the version is {after_reopen!r} after the refused reopen attempt, expected it to still "
        f"be 'Published' — a refused transition must leave the state untouched"
    )
    reopened_slice = _versions(ca, domain, repository, status="Unfinished", **scope)
    assert reopened_slice == set(), (
        f"ListPackageVersions(status='Unfinished') returned {sorted(reopened_slice)!r} after the "
        f"refused reopen; expected nothing"
    )

    # ---- positive control — a LEGAL status change on the same version does work ---------
    unlisted = _attempted_status_change(
        ca, domain, repository, package, "1.0.0", target="Unlisted", expected="Published")
    assert unlisted["succeeded"] is True, (
        f"moving the same version Published -> Unlisted {unlisted!r}; without this beat the "
        f"refusal above is indistinguishable from 'refuses every status update'"
    )
    after_unlist = _status(ca, domain, repository, "1.0.0", **scope)
    assert after_unlist == "Unlisted", (
        f"the version reads back as {after_unlist!r} after a successful move to Unlisted, expected "
        f"'Unlisted'"
    )
    # Restore, then re-prove the one-way clause from the restored state.
    back = _attempted_status_change(
        ca, domain, repository, package, "1.0.0", target="Published", expected="Unlisted")
    assert back["succeeded"] is True, (
        f"restoring the version to Published {back!r}"
    )
    reopen_again = _attempted_status_change(
        ca, domain, repository, package, "1.0.0", target="Unfinished", expected="Published")
    assert reopen_again["succeeded"] is False, (
        f"the second reopen attempt, from a version that had just been round-tripped through "
        f"Unlisted, {reopen_again!r}; the Unfinished target must be refused every time"
    )

    # Terminal read: an independent operation at the destination still serves the closing asset,
    # so the whole refused-transition sequence left a usable Published version behind.
    terminal = ca.get_package_version_asset(
        domain=domain, repository=repository, packageVersion="1.0.0", asset="closing.bin",
        **scope)["asset"].read()
    assert terminal == _ASSETS["closing.bin"], (
        f"after the refused transitions the closing asset serves {len(terminal)} bytes (sha256 "
        f"{hashlib.sha256(terminal).hexdigest()!r}), expected the published "
        f"{len(_ASSETS['closing.bin'])} bytes (sha256 "
        f"{hashlib.sha256(_ASSETS['closing.bin']).hexdigest()!r})"
    )


def _attempted_status_change(ca, domain: str, repository: str, package: str, version: str, *,
                             target: str, expected: str) -> dict:
    """Attempt a status change; `succeeded` means the version is in successfulVersions.

    Refusals arrive either in-band (failedVersions in a 200) or as an exception.
    """
    try:
        result = ca.update_package_versions_status(
            domain=domain, repository=repository, format="generic", namespace=_NAMESPACE,
            package=package, versions=[version], expectedStatus=expected, targetStatus=target)
    except ClientError as exc:
        return {"succeeded": False, "shape": "exception",
                "code": exc.response["Error"]["Code"],
                "message": exc.response["Error"].get("Message", "")}
    succeeded = version in result["successfulVersions"]
    return {"succeeded": succeeded, "shape": "response",
            "successfulVersions": result["successfulVersions"],
            "failedVersions": result["failedVersions"]}


def _status(ca, domain: str, repository: str, version: str, **scope) -> str:
    return ca.describe_package_version(
        domain=domain, repository=repository, packageVersion=version,
        **scope)["packageVersion"]["status"]


def _asset_names(ca, domain: str, repository: str, version: str, **scope) -> set[str]:
    """Every asset name across all pages of ListPackageVersionAssets."""
    out, next_token = set(), None
    while True:
        page = ca.list_package_version_assets(
            domain=domain, repository=repository, packageVersion=version, **scope,
            **({"nextToken": next_token} if next_token else {}))
        out.update(a["name"] for a in page["assets"])
        next_token = page.get("nextToken")
        if not next_token:
            return out


def _versions(ca, domain: str, repository: str, **kwargs) -> set[str]:
    """Every version across all pages of ListPackageVersions.

    A status filter matching nothing may answer ResourceNotFoundException, read as the empty set.
    """
    out, next_token = set(), None
    while True:
        try:
            page = ca.list_package_versions(
                domain=domain, repository=repository, **kwargs,
                **({"nextToken": next_token} if next_token else {}))
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return out
            raise
        out.update(v["version"] for v in page["versions"])
        next_token = page.get("nextToken")
        if not next_token:
            return out


def _delete_package(ca, domain: str, repository: str, package: str) -> None:
    try:
        ca.delete_package(domain=domain, repository=repository, format="generic",
                          namespace=_NAMESPACE, package=package)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _delete_repository(ca, domain: str, repository: str, timeout_s: float = 120.0) -> None:
    """DeleteRepository, retrying while the service still sees a dependent reference."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ca.delete_repository(domain=domain, repository=repository)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code != "ConflictException" or time.monotonic() >= deadline:
                raise
            time.sleep(3.0)


def _delete_domain(ca, domain: str, timeout_s: float = 120.0) -> None:
    """DeleteDomain, retrying while the service still sees a repository in the domain."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ca.delete_domain(domain=domain)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code != "ConflictException" or time.monotonic() >= deadline:
                raise
            time.sleep(3.0)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
