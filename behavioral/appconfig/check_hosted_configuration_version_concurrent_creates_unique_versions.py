"""hosted-configuration-version-concurrent-creates-unique-versions."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "hosted-configuration-version-concurrent-creates-unique-versions"
GROUP = 'hosted-configuration-version'
SERVICES = ['appconfig']


def _exc_error_code(exc) -> str:
    return (
        getattr(exc, "response", {}) or {}
    ).get("Error", {}).get("Code") or type(exc).__name__


def _run_parallel(fns):
    """Run zero-arg callables concurrently; return one {ok, value, error_code} dict per callable,
    in submission order."""

    def _wrap(fn):
        try:
            return {"ok": True, "value": fn(), "error_code": None}
        except Exception as exc:  # noqa: BLE001 - we classify below
            return {"ok": False, "value": None, "error_code": _exc_error_code(exc)}

    with ThreadPoolExecutor(max_workers=max(2, len(fns))) as pool:
        return list(pool.map(_wrap, fns))


def _ok_values(results):
    return [r["value"] for r in results if r["ok"]]


def _err_codes(results):
    return [r["error_code"] for r in results if not r["ok"]]


@tags("axis:happy-path", "cap:c2", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Five concurrent CreateHostedConfigurationVersion calls give the winners unique, contiguous
    version numbers from 1 that match the listing; every loser fails with ConflictException,
    because the service applies optimistic concurrency even without LatestVersionNumber.
    """
    ac = ctx.client("appconfig")

    app_id = ac.create_application(Name=ctx.unique_name("sim2real-behav-app-"))["Id"]
    ctx.on_cleanup(lambda: ac.delete_application(ApplicationId=app_id))

    cp_id = ac.create_configuration_profile(
        ApplicationId=app_id,
        Name=ctx.unique_name("sim2real-behav-cp-"),
        LocationUri="hosted",
    )["Id"]
    ctx.on_cleanup(
        lambda: ac.delete_configuration_profile(
            ApplicationId=app_id, ConfigurationProfileId=cp_id
        )
    )

    n = 5

    def make_creator(i):
        def _create():
            return ac.create_hosted_configuration_version(
                ApplicationId=app_id,
                ConfigurationProfileId=cp_id,
                Content=f'{{"n":{i}}}'.encode(),
                ContentType="application/json",
            )

        return _create

    results = _run_parallel([make_creator(i) for i in range(n)])
    successes = _ok_values(results)
    failures = _err_codes(results)

    # Register cleanup before asserting: AppConfig refuses DeleteConfigurationProfile while any
    # hosted configuration version survives.
    version_numbers = [r["VersionNumber"] for r in successes]
    for vn in version_numbers:
        ctx.on_cleanup(
            lambda vn=vn: ac.delete_hosted_configuration_version(
                ApplicationId=app_id, ConfigurationProfileId=cp_id, VersionNumber=vn
            )
        )

    assert len(successes) >= 1, results
    assert len(successes) + len(failures) == n, results

    assert set(failures) <= {"ConflictException"}, failures

    assert len(set(version_numbers)) == len(version_numbers), version_numbers
    assert sorted(version_numbers) == list(range(1, len(version_numbers) + 1)), version_numbers

    listed = ac.list_hosted_configuration_versions(
        ApplicationId=app_id, ConfigurationProfileId=cp_id
    )
    assert {item["VersionNumber"] for item in listed.get("Items", [])} == set(version_numbers)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
