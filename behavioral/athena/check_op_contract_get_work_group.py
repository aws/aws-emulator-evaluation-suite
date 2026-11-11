"""op-contract-get-work-group."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-get-work-group"
GROUP = "error-semantics"
SERVICES = ["athena"]


def _error(fn):
    """Call fn(); return its error (code, message). An unexpected SUCCESS raises, because an
    emulator accepting input real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetWorkGroup returns the Configuration exactly as supplied at creation
    (OutputLocation, EnforceWorkGroupConfiguration) and State starts ENABLED; it
    raises InvalidRequestException for a workgroup name that does not exist."""
    athena = ctx.client("athena")
    wg = ctx.unique_name("sim2real-wg-")
    output_prefix = f"s3://sim2real-athena-fake-bucket-{wg}/results/"
    athena.create_work_group(
        Name=wg,
        Description="behavioral-check workgroup",
        Configuration={
            "ResultConfiguration": {"OutputLocation": output_prefix},
            "EnforceWorkGroupConfiguration": True,
            "PublishCloudWatchMetricsEnabled": False,
        },
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: athena.delete_work_group(WorkGroup=wg))

    resp = athena.get_work_group(WorkGroup=wg)["WorkGroup"]
    assert resp["Name"] == wg, f"expected Name={wg!r}, got {resp['Name']!r}"
    assert resp["State"] == "ENABLED", f"expected State=ENABLED, got {resp['State']!r}"
    assert resp["Description"] == "behavioral-check workgroup", (
        f"expected Description='behavioral-check workgroup', got {resp['Description']!r}"
    )
    cfg = resp["Configuration"]
    assert cfg["ResultConfiguration"]["OutputLocation"] == output_prefix, (
        f"expected OutputLocation={output_prefix!r}, got {cfg['ResultConfiguration']['OutputLocation']!r}"
    )
    assert cfg["EnforceWorkGroupConfiguration"] is True, (
        f"expected EnforceWorkGroupConfiguration=True, got {cfg['EnforceWorkGroupConfiguration']!r}"
    )
    assert cfg["PublishCloudWatchMetricsEnabled"] is False, (
        f"expected PublishCloudWatchMetricsEnabled=False, got {cfg['PublishCloudWatchMetricsEnabled']!r}"
    )

    missing_wg = ctx.unique_name("sim2real-wg-missing-")
    code, message = _error(lambda: athena.get_work_group(WorkGroup=missing_wg))
    assert code == "InvalidRequestException", f"expected InvalidRequestException, got {code}"
    assert message == "WorkGroup is not found.", f"unexpected GetWorkGroup message: {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
