"""op-contract-deleteRealtimeLogConfig."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-deleteRealtimeLogConfig"
GROUP = "error-semantics"
SERVICES = ["cloudfront"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteRealtimeLogConfig rejects a request naming neither Name nor ARN (InvalidArgument), then
    succeeds by Name; Get and Update then fail NoSuchRealtimeLogConfig and the Name is reusable.
    """
    cf = ctx.client("cloudfront")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    name = ctx.unique_name("sim2real-rtlc-")
    # CreateRealtimeLogConfig validates only the format of the Kinesis stream and IAM role ARNs,
    # not their existence, so well-formed placeholder ARNs are enough.
    role_arn = f"arn:aws:iam::{account_id}:role/{name}-role"
    stream_arn = f"arn:aws:kinesis:{ctx.region}:{account_id}:stream/{name}-stream"

    def _endpoints():
        return [
            {
                "StreamType": "Kinesis",
                "KinesisStreamConfig": {"RoleARN": role_arn, "StreamARN": stream_arn},
            }
        ]

    created = cf.create_realtime_log_config(
        Name=name,
        EndPoints=_endpoints(),
        Fields=["timestamp", "c-ip", "time-to-first-byte"],
        SamplingRate=100,
    )
    assert created["RealtimeLogConfig"]["Name"] == name, (
        f"expected created config named {name!r}, got {created['RealtimeLogConfig']!r}"
    )
    ctx.on_cleanup(lambda: _safe_delete(cf, name))

    # distinct error boundary: neither Name nor ARN provided
    code, message = _error(lambda: cf.delete_realtime_log_config())
    assert code == "InvalidArgument", f"expected InvalidArgument, got {code}"
    assert message == "The parameter Name/ARN must be provided.", (
        f"expected the exact refusal message, got {message!r}"
    )

    cf.delete_realtime_log_config(Name=name)

    # confirm the effect: the config is gone, under an independent read...
    code_after, code_after_message = _error(lambda: cf.get_realtime_log_config(Name=name))
    assert code_after == "NoSuchRealtimeLogConfig", (
        f"expected NoSuchRealtimeLogConfig after delete, got {code_after}"
    )
    assert code_after_message == "The specified real-time log configuration does not exist.", (
        f"expected the exact refusal message, got {code_after_message!r}"
    )
    # ...and under a mutation, not just a read
    code_update, code_update_message = _error(lambda: cf.update_realtime_log_config(Name=name, SamplingRate=50))
    assert code_update == "NoSuchRealtimeLogConfig", (
        f"expected NoSuchRealtimeLogConfig updating a deleted config, got {code_update}"
    )
    assert code_update_message == "The specified real-time log configuration does not exist.", (
        f"expected the exact refusal message, got {code_update_message!r}"
    )

    # the freed Name is reusable
    recreated = cf.create_realtime_log_config(
        Name=name,
        EndPoints=_endpoints(),
        Fields=["timestamp"],
        SamplingRate=1,
    )
    assert recreated["RealtimeLogConfig"]["Name"] == name, (
        f"expected the freed name {name!r} to be reusable, got {recreated['RealtimeLogConfig']!r}"
    )


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected success raises,
    so a call AWS refuses is never read as a mere code mismatch.
    """
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _safe_delete(cf, name: str) -> None:
    try:
        cf.delete_realtime_log_config(Name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchRealtimeLogConfig":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
