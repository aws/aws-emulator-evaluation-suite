"""lookup-table-numeric-value-precision-preserved."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "lookup-table-numeric-value-precision-preserved"
GROUP = "state-machine"
SERVICES = ["logs"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A high-precision numeric value in a lookup table's CSV body comes back from GetLookupTable
    byte for byte, without rounding or reformatting.
    """
    logs = ctx.client("logs")
    table_name = ctx.unique_name("sim2realbehavlt").replace("-", "")

    high_precision_body = (
        "id,value\n"
        "1,3.14159265358979323846264338327950288419716939937510582097494459\n"
        "2,123456789012345678901234567890.123456789012345678901234567890\n"
        "3,0.000000000000000000000000000000000000000001234567890123456789\n"
    )

    create_resp = logs.create_lookup_table(
        lookupTableName=table_name,
        description="sim2real precision probe",
        tableBody=high_precision_body,
    )
    table_arn = create_resp["lookupTableArn"]
    ctx.on_cleanup(lambda: logs.delete_lookup_table(lookupTableArn=table_arn))

    got = _poll_for_table_body(ctx, table_arn)
    assert got == high_precision_body, (
        "lookup table tableBody was not preserved byte-for-byte "
        f"(precision loss suspected): sent {high_precision_body!r} got {got!r}"
    )


def _poll_for_table_body(ctx, table_arn, timeout_s=30.0):
    logs = ctx.client("logs")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        resp = logs.get_lookup_table(lookupTableArn=table_arn)
        last = resp.get("tableBody")
        if last is not None:
            return last
        time.sleep(1.0)
    raise AssertionError(f"lookup table body never became available: last={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
