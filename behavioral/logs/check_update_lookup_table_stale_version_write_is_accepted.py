"""update-lookup-table-stale-version-write-is-accepted."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "update-lookup-table-stale-version-write-is-accepted"
GROUP = "concurrency"
SERVICES = ["logs"]


@tags("axis:happy-path", "cap:c2", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateLookupTable has no version/ETag token, so a write from a stale view is accepted
    unconditionally and durably wins; a fabricated stale-version conflict fails the check.
    """
    logs = ctx.client("logs")
    table_name = ctx.unique_name("sim2real-behav-lut-").replace("-", "_")
    v1_body = "key,value\nseed,v1\n"
    created = logs.create_lookup_table(
        lookupTableName=table_name,
        tableBody=v1_body,
        tags={"Sim2RealOwner": "behavioral-suite"},
    )
    table_arn = created["lookupTableArn"]
    ctx.on_cleanup(lambda: logs.delete_lookup_table(lookupTableArn=table_arn))

    # This read is the only "version" the caller can act on; the API exposes no token.
    stale_view = logs.get_lookup_table(lookupTableArn=table_arn)["tableBody"]
    assert stale_view == v1_body, f"expected seed body {v1_body!r}, got {stale_view!r}"

    # A second writer updates the table out from under the reader's now-stale view.
    v2_body = "key,value\nseed,v2-overwritten-by-other-writer\n"
    logs.update_lookup_table(lookupTableArn=table_arn, tableBody=v2_body)
    _poll_lookup_table_body(ctx, table_arn, v2_body, timeout_s=30.0)

    # The original caller now writes again, still only holding its stale (v1) view and
    # passing no version/revision token -- because the API exposes none to pass. Real
    # AWS must accept this unconditionally rather than raising a stale-version conflict.
    v3_body = "key,value\nseed,v3-written-against-stale-view\n"
    response = logs.update_lookup_table(lookupTableArn=table_arn, tableBody=v3_body)
    assert response["lookupTableArn"] == table_arn, (
        f"expected {table_arn!r} echoed back, got {response.get('lookupTableArn')!r}"
    )

    # The write against the stale view must durably win -- not be silently dropped or
    # rejected -- confirming the operation is unconditional, not version-gated.
    final_body = _poll_lookup_table_body(ctx, table_arn, v3_body, timeout_s=30.0)
    assert final_body == v3_body, (
        f"write made against a stale view was not durably accepted: {final_body!r}"
    )



def _poll_lookup_table_body(
    ctx, table_arn: str, expected_body: str, timeout_s: float = 30.0, interval_s: float = 1.0
) -> str:
    logs = ctx.client("logs")
    deadline = time.monotonic() + timeout_s
    last_seen = ""
    while time.monotonic() < deadline:
        last_seen = logs.get_lookup_table(lookupTableArn=table_arn)["tableBody"]
        if last_seen == expected_body:
            return last_seen
        time.sleep(interval_s)
    raise AssertionError(
        f"lookup table content never converged to the expected write; last seen: {last_seen!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
