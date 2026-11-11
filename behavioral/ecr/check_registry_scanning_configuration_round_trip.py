"""registry-scanning-configuration-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "registry-scanning-configuration-round-trip"
GROUP = "data-plane"
SERVICES = ["ecr"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:ecr-registry-scanning")
def run(ctx) -> None:
    """A PutRegistryScanningConfiguration payload with repository filters and rules is
    returned unchanged by GetRegistryScanningConfiguration."""
    ecr = ctx.client("ecr")
    repo_prefix = ctx.unique_name("sim2real-ecr-scanrt-")

    original = ecr.get_registry_scanning_configuration()["scanningConfiguration"]

    def _restore():
        ecr.put_registry_scanning_configuration(
            scanType=original["scanType"], rules=original.get("rules", [])
        )

    ctx.on_cleanup(_restore)

    payload_rules = [{
        "scanFrequency": "SCAN_ON_PUSH",
        "repositoryFilters": [{"filter": f"{repo_prefix}*", "filterType": "WILDCARD"}],
    }]

    put_resp = ecr.put_registry_scanning_configuration(scanType="BASIC", rules=payload_rules)
    put_config = put_resp["registryScanningConfiguration"]
    assert put_config["scanType"] == "BASIC", f"expected scanType BASIC, got {put_config['scanType']!r}"
    assert put_config["rules"] == payload_rules, (
        f"put response rules do not match what was sent: expected {payload_rules}, got {put_config['rules']}"
    )

    get_resp = ecr.get_registry_scanning_configuration()
    get_config = get_resp["scanningConfiguration"]
    assert get_config["scanType"] == "BASIC", f"expected scanType BASIC, got {get_config['scanType']!r}"
    assert get_config["rules"] == payload_rules, (
        f"independent Get did not reflect the Put: expected {payload_rules}, got {get_config['rules']}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
