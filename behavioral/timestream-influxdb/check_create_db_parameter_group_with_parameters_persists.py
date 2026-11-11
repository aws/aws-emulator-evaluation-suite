"""create-db-parameter-group-with-parameters-persists."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-db-parameter-group-with-parameters-persists"
GROUP = "control-plane"
SERVICES = ["timestream-influxdb"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateDbParameterGroup persists the customer-supplied InfluxDB v2 parameter
    values exactly, and GetDbParameterGroup returns the same values back."""
    influx = ctx.client("timestream-influxdb")
    name = ctx.unique_name("sim2real-pgparams-")
    parameters = {
        "InfluxDBv2": {
            "fluxLogEnabled": True,
            "queryConcurrency": 42,
            "queryQueueSize": 10,
            "logLevel": "debug",
        }
    }

    created = influx.create_db_parameter_group(name=name, parameters=parameters)
    created_params = created["parameters"]["InfluxDBv2"]
    assert created_params["fluxLogEnabled"] is True, (
        f"expected fluxLogEnabled=True in create response, got {created_params.get('fluxLogEnabled')!r}"
    )
    assert created_params["queryConcurrency"] == 42, (
        f"expected queryConcurrency=42 in create response, got {created_params.get('queryConcurrency')!r}"
    )
    assert created_params["queryQueueSize"] == 10, (
        f"expected queryQueueSize=10 in create response, got {created_params.get('queryQueueSize')!r}"
    )
    assert created_params["logLevel"] == "debug", (
        f"expected logLevel='debug' in create response, got {created_params.get('logLevel')!r}"
    )

    fetched = influx.get_db_parameter_group(identifier=created["id"])
    fetched_params = fetched["parameters"]["InfluxDBv2"]
    assert fetched_params["fluxLogEnabled"] is True, (
        f"expected fluxLogEnabled=True on independent GetDbParameterGroup read, got {fetched_params.get('fluxLogEnabled')!r}"
    )
    assert fetched_params["queryConcurrency"] == 42, (
        f"expected queryConcurrency=42 on independent GetDbParameterGroup read, got {fetched_params.get('queryConcurrency')!r}"
    )
    assert fetched_params["queryQueueSize"] == 10, (
        f"expected queryQueueSize=10 on independent GetDbParameterGroup read, got {fetched_params.get('queryQueueSize')!r}"
    )
    assert fetched_params["logLevel"] == "debug", (
        f"expected logLevel='debug' on independent GetDbParameterGroup read, got {fetched_params.get('logLevel')!r}"
    )
    # Note: no DeleteDbParameterGroup API exists (confirmed against the
    # timestream-influxdb service model); nothing to clean up.


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
