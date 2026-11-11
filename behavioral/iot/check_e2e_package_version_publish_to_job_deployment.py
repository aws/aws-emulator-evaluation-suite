"""e2e-package-version-publish-to-job-deployment."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "e2e-package-version-publish-to-job-deployment"
GROUP = "e2e"
SERVICES = ["iot"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:iot-indexing")
def run(ctx) -> None:
    """A package version's attribute is substituted into a job document through the
    ${aws:iot:package:...:attributes:...} placeholder only after CreateJob references the
    PUBLISHED package version via destinationPackageVersions."""
    iot = ctx.client("iot")

    _ensure_package_shadow_indexing(ctx, iot)

    thing_name = ctx.unique_name("sim2real-pkgjob-thing-")
    thing_arn = iot.create_thing(thingName=thing_name)["thingArn"]
    ctx.on_cleanup(lambda: iot.delete_thing(thingName=thing_name))

    package_name = ctx.unique_name("sim2real-pkg-")
    iot.create_package(packageName=package_name, tags={"sim2real-audit": "package-version-publish-to-job-deployment"})
    ctx.on_cleanup(lambda: iot.delete_package(packageName=package_name))

    version_name = "1.0.0"
    firmware_url = "https://example-bucket.s3.us-west-2.amazonaws.com/firmware-image.bin"
    iot.create_package_version(
        packageName=package_name,
        versionName=version_name,
        attributes={"firmwareUrl": firmware_url},
        tags={"sim2real-audit": "package-version-publish-to-job-deployment"},
    )
    ctx.on_cleanup(lambda: iot.delete_package_version(packageName=package_name, versionName=version_name))

    iot.update_package_version(packageName=package_name, versionName=version_name, action="PUBLISH")

    published = iot.get_package_version(packageName=package_name, versionName=version_name)
    assert published["status"] == "PUBLISHED", (
        f"package version {version_name!r} status was {published['status']!r} after PUBLISH, expected 'PUBLISHED'"
    )
    package_version_arn = published["packageVersionArn"]

    job_id = ctx.unique_name("sim2real-pkgjob-")
    job_document = (
        '{"firmwareUrl": "${aws:iot:package:'
        + package_name
        + ":version:"
        + version_name
        + ':attributes:firmwareUrl}"}'
    )
    iot.create_job(
        jobId=job_id,
        targets=[thing_arn],
        targetSelection="SNAPSHOT",
        document=job_document,
        destinationPackageVersions=[package_version_arn],
        tags=[{"Key": "sim2real-audit", "Value": "package-version-publish-to-job-deployment"}],
    )
    ctx.on_cleanup(lambda: iot.delete_job(jobId=job_id, force=True))

    described_job = iot.describe_job(jobId=job_id)["job"]
    assert described_job["destinationPackageVersions"] == [package_version_arn], (
        f"describe_job returned destinationPackageVersions={described_job['destinationPackageVersions']!r}, "
        f"expected [{package_version_arn!r}]"
    )

    doc = iot.get_job_document(jobId=job_id)["document"]
    assert firmware_url in doc, (
        f"job document was not substituted with the published package version's attribute: {doc}"
    )
    assert "${aws:iot:package" not in doc, "unsubstituted placeholder leaked into the job document"


# ===== helpers =====
def _ensure_package_shadow_indexing(ctx, iot) -> None:
    """CreatePackage fails with ValidationException ("Enable fleet indexing for
    '$package' named shadow.") unless the account's fleet indexing is configured to
    index the reserved $package named shadow -- an account-wide, region-wide
    prerequisite documented for the Software Package Catalog. Enable it
    idempotently and restore the prior configuration afterward."""
    before = iot.get_indexing_configuration().get("thingIndexingConfiguration", {})
    already_on = (
        before.get("namedShadowIndexingMode") == "ON"
        and "$package" in (before.get("filter", {}) or {}).get("namedShadowNames", [])
    )
    if already_on:
        return

    prior_mode = before.get("thingIndexingMode", "OFF")
    prior_filter = before.get("filter", {}) or {}
    prior_named_shadow_mode = before.get("namedShadowIndexingMode", "OFF")
    prior_shadow_names = list(prior_filter.get("namedShadowNames", []))

    new_thing_mode = "REGISTRY" if prior_mode == "OFF" else prior_mode
    iot.update_indexing_configuration(
        thingIndexingConfiguration={
            "thingIndexingMode": new_thing_mode,
            "namedShadowIndexingMode": "ON",
            "filter": {"namedShadowNames": list(set(prior_shadow_names + ["$package"]))},
        }
    )

    def _restore():
        iot.update_indexing_configuration(
            thingIndexingConfiguration={
                "thingIndexingMode": prior_mode,
                "namedShadowIndexingMode": prior_named_shadow_mode,
                "filter": {"namedShadowNames": prior_shadow_names},
            }
        )

    ctx.on_cleanup(_restore)
    _wait_for_shadow_indexing_on(iot, timeout_s=30)


def _wait_for_shadow_indexing_on(iot, timeout_s: float = 30.0) -> None:
    import time

    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        cfg = iot.get_indexing_configuration().get("thingIndexingConfiguration", {})
        if cfg.get("namedShadowIndexingMode") == "ON" and "$package" in (
            cfg.get("filter", {}) or {}
        ).get("namedShadowNames", []):
            return
        time.sleep(2)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
