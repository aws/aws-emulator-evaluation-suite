"""op-contract-get-realtime-log-config."""
from __future__ import annotations

from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-get-realtime-log-config"
GROUP = "error-semantics"
SERVICES = ["cloudfront"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetRealtimeLogConfig returns the created config by Name, rejects (InvalidArgument) a request
    that supplies neither Name nor ARN, and once the config is deleted an independent read by the
    same Name returns NoSuchRealtimeLogConfig."""
    cf = ctx.client("cloudfront")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    name = ctx.unique_name("sim2real-rtlc-")
    fields = ["timestamp", "c-ip"]

    create_resp = cf.create_realtime_log_config(
        Name=name,
        EndPoints=[
            {
                "StreamType": "Kinesis",
                "KinesisStreamConfig": {
                    "RoleARN": f"arn:aws:iam::{account_id}:role/sim2real-nonexistent-realtime-log-role",
                    "StreamARN": f"arn:aws:kinesis:{ctx.region}:{account_id}:stream/sim2real-nonexistent-stream",
                },
            }
        ],
        Fields=fields,
        SamplingRate=50,
    )
    arn = create_resp["RealtimeLogConfig"]["ARN"]
    ctx.on_cleanup(lambda: _safe_delete(cf, name))

    # success path
    got = cf.get_realtime_log_config(Name=name)
    config = got["RealtimeLogConfig"]
    assert config["SamplingRate"] == 50
    assert config["Fields"] == fields
    assert config["ARN"] == arn

    # error boundary: neither Name nor ARN supplied
    err_missing, msg_missing = _error(lambda: cf.get_realtime_log_config())
    assert err_missing == "InvalidArgument", f"expected InvalidArgument (missing), got {err_missing}"
    assert msg_missing == "The parameter Name/ARN must be provided.", (
        f"expected AWS's exact missing-identifier message, got {msg_missing!r}"
    )

    # the delete this check already performs is proven, not just executed: an independent
    # read of the same Name afterwards must come back not-found
    cf.delete_realtime_log_config(Name=name)
    err_after_delete, msg_after_delete = _error(lambda: cf.get_realtime_log_config(Name=name))
    assert err_after_delete == "NoSuchRealtimeLogConfig", (
        f"expected NoSuchRealtimeLogConfig after delete, got {err_after_delete}"
    )
    assert msg_after_delete == "The specified real-time log configuration does not exist.", (
        f"expected AWS's exact not-found message after delete, got {msg_after_delete!r}"
    )


def _error(fn: Callable[[], Any]) -> tuple[str, str]:
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
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
