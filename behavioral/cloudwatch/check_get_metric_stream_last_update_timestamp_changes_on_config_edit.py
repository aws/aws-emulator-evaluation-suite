"""get-metric-stream-last-update-timestamp-changes-on-config-edit."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "get-metric-stream-last-update-timestamp-changes-on-config-edit"
GROUP = "telemetry"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetMetricStream's LastUpdateDate advances (while CreationDate stays
    fixed) when the stream's filter configuration is edited via a subsequent
    PutMetricStream call on the same name."""
    cw = ctx.client("cloudwatch")
    sts = ctx.client("sts")
    account = sts.get_caller_identity()["Account"]

    name = ctx.unique_name("sim2real-behav-mstream-")
    firehose_arn = f"arn:aws:firehose:{ctx.region}:{account}:deliverystream/{name}"
    role_arn = f"arn:aws:iam::{account}:role/{name}"

    cw.put_metric_stream(
        Name=name,
        FirehoseArn=firehose_arn,
        RoleArn=role_arn,
        OutputFormat="json",
        IncludeFilters=[{"Namespace": "AWS/EC2"}],
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )

    # DeleteMetricStream of an already-deleted name succeeds, so any error is a real failure.
    ctx.on_cleanup(lambda: cw.delete_metric_stream(Name=name))

    initial = cw.get_metric_stream(Name=name)
    creation_date = initial["CreationDate"]
    last_update_v1 = initial["LastUpdateDate"]
    assert initial["IncludeFilters"] == [{"Namespace": "AWS/EC2"}], (
        f"expected seed IncludeFilters [AWS/EC2], got {initial['IncludeFilters']}"
    )

    # LastUpdateDate's resolution may not distinguish two writes issued back to
    # back, so retry the edit itself (idempotent — same params each call) until
    # the timestamp actually advances, bounded by a deadline.
    updated = None
    deadline = time.monotonic() + 30.0
    while time.monotonic() < deadline:
        cw.put_metric_stream(
            Name=name,
            FirehoseArn=firehose_arn,
            RoleArn=role_arn,
            OutputFormat="json",
            IncludeFilters=[{"Namespace": "AWS/Lambda"}],
        )
        current = cw.get_metric_stream(Name=name)
        if current["LastUpdateDate"] > last_update_v1:
            updated = current
            break
        time.sleep(2)

    assert updated is not None, (
        f"GetMetricStream LastUpdateDate never advanced past {last_update_v1} "
        f"after editing filters via PutMetricStream"
    )
    assert updated["CreationDate"] == creation_date, (
        f"expected CreationDate to stay fixed at {creation_date}, got {updated['CreationDate']}"
    )
    assert updated["IncludeFilters"] == [{"Namespace": "AWS/Lambda"}], (
        f"expected updated IncludeFilters [AWS/Lambda], got {updated['IncludeFilters']}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
