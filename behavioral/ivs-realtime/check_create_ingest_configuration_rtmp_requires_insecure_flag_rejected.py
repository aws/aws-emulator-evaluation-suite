"""create-ingest-configuration-rtmp-requires-insecure-flag-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-ingest-configuration-rtmp-requires-insecure-flag-rejected"
GROUP = "overly-permissive"
SERVICES = ["ivs-realtime"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateIngestConfiguration with ingestProtocol=RTMP is rejected unless
    insecureIngest=True is explicitly set."""
    ivsrt = ctx.client("ivs-realtime")

    rejected_name = ctx.unique_name("sim2real-ivsrt-ingest-")
    error = _client_error(
        lambda: ivsrt.create_ingest_configuration(name=rejected_name, ingestProtocol="RTMP")
    )
    assert error.get("Code") == "ValidationException", f"expected ValidationException, got {error!r}"
    assert error.get("Message") == (
        "Request member: ingestProtocol failed to satisfy the constraints: "
        "insecure ingest is required for Ingest RTMP protocol"
    ), error

    # Effect absent: the rejected name does not exist, via an independent read.
    names_after_reject = {c["name"] for c in ivsrt.list_ingest_configurations()["ingestConfigurations"]}
    assert rejected_name not in names_after_reject, f"{rejected_name} should not have been created"

    # Positive control: the same request with insecureIngest=True succeeds.
    created = ivsrt.create_ingest_configuration(
        name=ctx.unique_name("sim2real-ivsrt-ingest-"),
        ingestProtocol="RTMP",
        insecureIngest=True,
        tags={"sim2real": "true"},
    )["ingestConfiguration"]
    ctx.on_cleanup(lambda: ivsrt.delete_ingest_configuration(arn=created["arn"]))
    assert created["ingestProtocol"] == "RTMP", created["ingestProtocol"]

    # Terminal read: independent of the create call, at the destination.
    fetched = ivsrt.get_ingest_configuration(arn=created["arn"])["ingestConfiguration"]
    assert fetched["ingestProtocol"] == "RTMP", fetched["ingestProtocol"]
    assert fetched["name"] == created["name"], fetched["name"]


def _client_error(fn) -> dict:
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")



if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
