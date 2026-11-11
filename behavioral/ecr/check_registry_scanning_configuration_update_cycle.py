"""registry-scanning-configuration-update-cycle."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "registry-scanning-configuration-update-cycle"
GROUP = "state-machine"
SERVICES = ["ecr"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:ecr-registry-scanning")
def run(ctx) -> None:
    """PutRegistryScanningConfiguration transitions the registry between BASIC and ENHANCED
    scan modes, and the new rule set (scan frequency + repository filters) persists across
    a subsequent GetRegistryScanningConfiguration call for each mode."""
    from botocore.exceptions import ClientError

    ecr = ctx.client("ecr")

    original = ecr.get_registry_scanning_configuration()["scanningConfiguration"]

    def _restore() -> None:
        ecr.put_registry_scanning_configuration(
            scanType=original.get("scanType", "BASIC"), rules=original.get("rules", [])
        )

    ctx.on_cleanup(_restore)

    basic_rule = {"scanFrequency": "SCAN_ON_PUSH", "repositoryFilters": []}
    put_basic = ecr.put_registry_scanning_configuration(scanType="BASIC", rules=[basic_rule])
    put_basic_conf = put_basic["registryScanningConfiguration"]
    assert put_basic_conf["scanType"] == "BASIC", (
        f"expected PutRegistryScanningConfiguration(BASIC) to echo scanType=BASIC, "
        f"got {put_basic_conf['scanType']!r}"
    )
    assert put_basic_conf["rules"] == [basic_rule], (
        f"expected PutRegistryScanningConfiguration(BASIC) to echo rules={[basic_rule]!r}, "
        f"got {put_basic_conf['rules']!r}"
    )

    get_basic = ecr.get_registry_scanning_configuration()["scanningConfiguration"]
    assert get_basic["scanType"] == "BASIC", (
        f"expected GetRegistryScanningConfiguration to reflect scanType=BASIC after the put, "
        f"got {get_basic['scanType']!r}"
    )
    assert get_basic["rules"] == [basic_rule], (
        f"expected GetRegistryScanningConfiguration to reflect rules={[basic_rule]!r} after the put, "
        f"got {get_basic['rules']!r}"
    )

    enhanced_rule = {
        "scanFrequency": "CONTINUOUS_SCAN",
        "repositoryFilters": [{"filter": "*", "filterType": "WILDCARD"}],
    }
    try:
        put_enhanced = ecr.put_registry_scanning_configuration(
            scanType="ENHANCED", rules=[enhanced_rule]
        )
    except ClientError as err:
        if err.response["Error"]["Code"] == "BlockedByOrganizationPolicyException":
            raise AssertionError(
                "an AWS Organizations policy on this account blocks enabling ENHANCED "
                "registry scanning; would close by running against an account/OU without "
                "that SCP restriction"
            )
        raise
    put_enhanced_conf = put_enhanced["registryScanningConfiguration"]
    assert put_enhanced_conf["scanType"] == "ENHANCED", (
        f"expected PutRegistryScanningConfiguration(ENHANCED) to echo scanType=ENHANCED, "
        f"got {put_enhanced_conf['scanType']!r}"
    )
    assert put_enhanced_conf["rules"] == [enhanced_rule], (
        f"expected PutRegistryScanningConfiguration(ENHANCED) to echo rules={[enhanced_rule]!r}, "
        f"got {put_enhanced_conf['rules']!r}"
    )

    get_enhanced = ecr.get_registry_scanning_configuration()["scanningConfiguration"]
    assert get_enhanced["scanType"] == "ENHANCED", (
        f"expected GetRegistryScanningConfiguration to reflect scanType=ENHANCED after the put, "
        f"got {get_enhanced['scanType']!r}"
    )
    assert get_enhanced["rules"] == [enhanced_rule], (
        f"expected GetRegistryScanningConfiguration to reflect rules={[enhanced_rule]!r} after the put, "
        f"got {get_enhanced['rules']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
