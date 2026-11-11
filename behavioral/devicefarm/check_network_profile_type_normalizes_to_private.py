"""network-profile-type-normalizes-to-private."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "network-profile-type-normalizes-to-private"
GROUP = 'network-profile'
SERVICES = ['devicefarm']


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


@tags("axis:happy-path", "cap:c2", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A custom network profile is always stored as type PRIVATE: requesting the CURATED
    type (reserved for AWS's own built-in profiles) is silently normalized, and the
    normalized type survives an independent read, not just the create echo.
    """
    df = ctx.client("devicefarm")
    project_name = ctx.unique_name("sim2real-behav-df-np-project-")
    project_arn = df.create_project(name=project_name)["project"]["arn"]
    ctx.on_cleanup(_teardown(lambda: df.delete_project(arn=project_arn), "NotFoundException"))

    profile_name = ctx.unique_name("sim2real-behav-df-np-curated-")
    created = df.create_network_profile(
        projectArn=project_arn, name=profile_name, type="CURATED", uplinkBandwidthBits=123456,
    )["networkProfile"]
    ctx.on_cleanup(_teardown(lambda: df.delete_network_profile(arn=created["arn"]), "NotFoundException"))
    assert created["type"] == "PRIVATE", (
        f"requested type CURATED, CreateNetworkProfile echoed {created['type']!r}, expected PRIVATE"
    )
    assert created["uplinkBandwidthBits"] == 123456, (
        f"expected the requested uplinkBandwidthBits to persist, got {created['uplinkBandwidthBits']!r}"
    )

    read_back = df.get_network_profile(arn=created["arn"])["networkProfile"]
    assert read_back["type"] == "PRIVATE", (
        f"a later GetNetworkProfile read back type {read_back['type']!r}, expected the "
        f"normalized PRIVATE to persist rather than reverting to the requested CURATED"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
