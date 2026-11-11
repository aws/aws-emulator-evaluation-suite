"""update-ingest-configuration-not-found-rejected."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "update-ingest-configuration-not-found-rejected"
GROUP = "error-semantics"
SERVICES = ["ivs-realtime"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateIngestConfiguration on an ARN that doesn't reference an existing ingest
    configuration is rejected with ResourceNotFoundException, while updating a real one
    still succeeds."""
    ivsrt = ctx.client("ivs-realtime")
    bogus_arn = (
        f"arn:aws:ivs:{ctx.region}:{ctx.account}:ingest-configuration/{uuid.uuid4().hex[:12]}"
    )

    error = _client_error(
        lambda: ivsrt.update_ingest_configuration(arn=bogus_arn, redundantIngest=True)
    )
    assert error["Code"] == "ResourceNotFoundException", error
    assert error["Message"] == f"Resource: {bogus_arn} not found", (
        f"unexpected UpdateIngestConfiguration not-found message: {error['Message']!r}"
    )

    # Positive control: updating a real ingest configuration succeeds.
    created = ivsrt.create_ingest_configuration(
        name=ctx.unique_name("sim2real-ivsrt-ingest-"), ingestProtocol="RTMPS"
    )["ingestConfiguration"]
    ctx.on_cleanup(lambda: ivsrt.delete_ingest_configuration(arn=created["arn"]))
    updated = ivsrt.update_ingest_configuration(arn=created["arn"], redundantIngest=True)[
        "ingestConfiguration"
    ]
    assert updated["redundantIngest"] is True, updated["redundantIngest"]

    # Independent read at the destination: the mutating call's own echo is not enough.
    fetched = ivsrt.get_ingest_configuration(arn=created["arn"])["ingestConfiguration"]
    assert fetched["redundantIngest"] is True, fetched["redundantIngest"]


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
