"""registry-scanning-configuration-lifecycle."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "registry-scanning-configuration-lifecycle"
GROUP = "state-machine"
SERVICES = ["ecr"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:ecr-registry-scanning")
def run(ctx) -> None:
    """PutRegistryScanningConfiguration with one BASIC SCAN_ON_PUSH rule on filter * is returned
    by GetRegistryScanningConfiguration, and BatchGetRepositoryScanningConfiguration reports
    SCAN_ON_PUSH for a repository under it."""
    ecr = ctx.client("ecr")

    original = ecr.get_registry_scanning_configuration()["scanningConfiguration"]

    def _restore():
        ecr.put_registry_scanning_configuration(
            scanType=original.get("scanType", "BASIC"),
            rules=original.get("rules", []),
        )

    ctx.on_cleanup(_restore)

    repo_name = ctx.unique_name("sim2real-ecr-scanconf-")
    ecr.create_repository(
        repositoryName=repo_name, tags=[{"Key": "sim2real", "Value": CHECK}]
    )
    ctx.on_cleanup(lambda: ecr.delete_repository(repositoryName=repo_name, force=True))

    put_resp = ecr.put_registry_scanning_configuration(
        scanType="BASIC",
        rules=[
            {
                "scanFrequency": "SCAN_ON_PUSH",
                "repositoryFilters": [{"filter": "*", "filterType": "WILDCARD"}],
            }
        ],
    )
    put_scan_type = put_resp["registryScanningConfiguration"]["scanType"]
    assert put_scan_type == "BASIC", f"expected BASIC, got {put_scan_type!r}"

    get_resp = ecr.get_registry_scanning_configuration()["scanningConfiguration"]
    assert get_resp["scanType"] == "BASIC", (
        f"expected GetRegistryScanningConfiguration to echo BASIC, got {get_resp['scanType']!r}"
    )
    assert len(get_resp["rules"]) == 1, f"expected exactly 1 rule, got {len(get_resp['rules'])}"
    assert get_resp["rules"][0]["scanFrequency"] == "SCAN_ON_PUSH", (
        f"expected SCAN_ON_PUSH, got {get_resp['rules'][0]['scanFrequency']!r}"
    )
    assert get_resp["rules"][0]["repositoryFilters"][0]["filter"] == "*", (
        f"expected wildcard filter '*', got "
        f"{get_resp['rules'][0]['repositoryFilters'][0]['filter']!r}"
    )

    batch_resp = _poll_until(
        lambda: ecr.batch_get_repository_scanning_configuration(repositoryNames=[repo_name]),
        lambda resp: (
            not resp["failures"]
            and resp["scanningConfigurations"]
            and resp["scanningConfigurations"][0].get("scanFrequency") == "SCAN_ON_PUSH"
        ),
        timeout_s=30.0,
    )
    assert batch_resp["failures"] == [], f"expected no failures, got {batch_resp['failures']}"
    configs = batch_resp["scanningConfigurations"]
    assert len(configs) == 1, f"expected exactly 1 config, got {len(configs)}"
    assert configs[0]["repositoryName"] == repo_name, (
        f"expected {repo_name!r}, got {configs[0]['repositoryName']!r}"
    )
    assert configs[0]["scanFrequency"] == "SCAN_ON_PUSH", (
        f"expected the registry-wide wildcard rule to apply as SCAN_ON_PUSH, "
        f"got {configs[0]['scanFrequency']!r}"
    )
    assert isinstance(configs[0]["scanOnPush"], bool), (
        f"expected scanOnPush to be a bool, got {configs[0]['scanOnPush']!r}"
    )


def _poll_until(probe, predicate, *, timeout_s=30.0, interval_s=1.5):
    import time

    deadline = time.monotonic() + timeout_s
    value = probe()
    while time.monotonic() < deadline:
        value = probe()
        if predicate(value):
            return value
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last value: {value!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
