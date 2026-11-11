"""delete-metric-stream-immediately-absent-from-list."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-metric-stream-immediately-absent-from-list"
GROUP = "telemetry"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A deleted metric stream disappears from ListMetricStreams on the very
    next call -- no stale-entry observability window."""
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
        Tags=[{"Key": "sim2real-owner", "Value": "delete-metric-stream-immediately-absent-from-list"}],
    )

    # DeleteMetricStream of an already-deleted name succeeds, so any error is a real failure.
    ctx.on_cleanup(lambda: cw.delete_metric_stream(Name=name))

    assert name in _list_all_metric_stream_names(cw), (
        f"newly created metric stream {name} not visible in ListMetricStreams"
    )

    cw.delete_metric_stream(Name=name)

    names_after = _list_all_metric_stream_names(cw)
    assert name not in names_after, (
        f"deleted metric stream {name} still appears in ListMetricStreams: {names_after}"
    )

    code, message = _error(lambda: cw.get_metric_stream(Name=name))
    assert code == "ResourceNotFoundException", (
        f"expected GetMetricStream on deleted stream {name} to fail with "
        f"ResourceNotFoundException, got {code!r}"
    )
    expected_message = ""  # real AWS returns an empty Message for this code
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


# ===== helpers =====
def _list_all_metric_stream_names(cw) -> list[str]:
    names: list[str] = []
    token = None
    while True:
        kwargs = {"NextToken": token} if token else {}
        resp = cw.list_metric_streams(**kwargs)
        names.extend(e["Name"] for e in resp.get("Entries", []))
        token = resp.get("NextToken")
        if not token:
            break
    return names


def _error(fn):
    """Call fn(); return the botocore (Code, Message). An unexpected SUCCESS raises, so a target
    accepting a call AWS refuses is reported as such rather than as a code mismatch."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
