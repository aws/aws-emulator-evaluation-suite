"""list-instrumentation-configurations-reflects-created-config."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-instrumentation-configurations-reflects-created-config"
GROUP = "data-plane"
SERVICES = ["application-signals"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListInstrumentationConfigurations returns the configuration created for its
    Service/Environment/InstrumentationType with matching Location and LocationHash, and a
    different Environment or InstrumentationType does not return it."""
    sig = ctx.client("application-signals")
    service = ctx.unique_name("sim2real-app-")
    environment = ctx.unique_name("sim2real-env-")
    other_environment = ctx.unique_name("sim2real-env-")
    file_path = "src/catalog/CatalogService.py"

    created = sig.create_instrumentation_configuration(
        InstrumentationType="PROBE",
        Service=service,
        Environment=environment,
        SignalType="SNAPSHOT",
        Location=_code_location(file_path, method_name="lookupItem"),
        CaptureConfiguration=_capture_configuration(),
    )
    location_hash = created["LocationHash"]
    ctx.on_cleanup(
        lambda: _delete_instrumentation_ignore_missing(sig, service, environment, location_hash)
    )

    resp = sig.list_instrumentation_configurations(
        Service=service,
        Environment=environment,
        InstrumentationType="PROBE",
    )
    assert resp["Service"] == service, f"expected Service {service!r}, got {resp['Service']!r}"
    assert resp["Environment"] == environment, (
        f"expected Environment {environment!r}, got {resp['Environment']!r}"
    )
    hashes = [cfg["LocationHash"] for cfg in resp["LatestConfigurations"]]
    assert location_hash in hashes, f"expected {location_hash!r} among {hashes!r}"
    matching = next(c for c in resp["LatestConfigurations"] if c["LocationHash"] == location_hash)
    assert matching["Location"]["CodeLocation"]["FilePath"] == file_path, (
        f"expected FilePath {file_path!r}, got {matching['Location']['CodeLocation']['FilePath']!r}"
    )
    assert matching["InstrumentationType"] == "PROBE", (
        f"expected InstrumentationType PROBE, got {matching['InstrumentationType']!r}"
    )

    # The listing must scope, not echo: the same service under another environment, and under
    # another instrumentation type, must not return this configuration.
    other_env_resp = sig.list_instrumentation_configurations(
        Service=service,
        Environment=other_environment,
        InstrumentationType="PROBE",
    )
    other_env_hashes = [cfg["LocationHash"] for cfg in other_env_resp["LatestConfigurations"]]
    assert location_hash not in other_env_hashes, (
        f"config created in {environment!r} leaked into unrelated environment "
        f"{other_environment!r}: {other_env_hashes!r}"
    )

    other_type_resp = sig.list_instrumentation_configurations(
        Service=service,
        Environment=environment,
        InstrumentationType="BREAKPOINT",
    )
    other_type_hashes = [cfg["LocationHash"] for cfg in other_type_resp["LatestConfigurations"]]
    assert location_hash not in other_type_hashes, (
        f"PROBE config leaked into a BREAKPOINT-scoped list: {other_type_hashes!r}"
    )


def _delete_instrumentation_ignore_missing(sig, service, environment, location_hash) -> None:
    try:
        sig.delete_instrumentation_configuration(
            InstrumentationType="PROBE",
            Service=service,
            Environment=environment,
            SignalType="SNAPSHOT",
            LocationIdentifier={"LocationHash": location_hash},
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _code_location(file_path: str, method_name: str | None = None) -> dict:
    loc = {"Language": "Python", "FilePath": file_path, "CodeUnit": "sim2real_module"}
    if method_name:
        loc["MethodName"] = method_name
    return {"CodeLocation": loc}


def _capture_configuration(max_hits: int = 50) -> dict:
    return {"CodeCapture": {"CaptureLimits": {"MaxHits": max_hits}}}


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
