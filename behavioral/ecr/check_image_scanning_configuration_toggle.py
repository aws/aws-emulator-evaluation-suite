"""image-scanning-configuration-toggle."""
from __future__ import annotations

from behavioral_harness import tags

def _create_repo(ecr, ctx, name=None, **kwargs):
    """CreateRepository + register force-delete teardown; returns the repository dict."""
    name = name or ctx.unique_name("sim2real-behav-ecr-repo-")
    resp = ecr.create_repository(repositoryName=name, **kwargs)
    ctx.on_cleanup(lambda: ecr.delete_repository(repositoryName=name, force=True))
    return resp["repository"]

CHECK = "image-scanning-configuration-toggle"
GROUP = 'scanning'
SERVICES = ['ecr']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutImageScanningConfiguration flips scanOnPush in both directions, and each flip is
    durably reflected by an independent DescribeRepositories read, not just the mutating
    call's own response."""
    ecr = ctx.client("ecr")
    name = ctx.unique_name("sim2real-behav-ecr-repo-")
    _create_repo(ecr, ctx, name, imageScanningConfiguration={"scanOnPush": False})

    described = ecr.describe_repositories(repositoryNames=[name])["repositories"][0]
    assert described["imageScanningConfiguration"]["scanOnPush"] is False, (
        f"expected a freshly created repository with scanOnPush=False to read back False, "
        f"got {described['imageScanningConfiguration']['scanOnPush']!r}"
    )

    ecr.put_image_scanning_configuration(
        repositoryName=name, imageScanningConfiguration={"scanOnPush": True}
    )
    described = ecr.describe_repositories(repositoryNames=[name])["repositories"][0]
    assert described["imageScanningConfiguration"]["scanOnPush"] is True, (
        f"expected PutImageScanningConfiguration(scanOnPush=True) to be durably reflected, "
        f"got {described['imageScanningConfiguration']['scanOnPush']!r}"
    )

    ecr.put_image_scanning_configuration(
        repositoryName=name, imageScanningConfiguration={"scanOnPush": False}
    )
    described = ecr.describe_repositories(repositoryNames=[name])["repositories"][0]
    assert described["imageScanningConfiguration"]["scanOnPush"] is False, (
        f"expected PutImageScanningConfiguration(scanOnPush=False) to flip it back, "
        f"got {described['imageScanningConfiguration']['scanOnPush']!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
