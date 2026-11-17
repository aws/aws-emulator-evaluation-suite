"""realtime-log-config-mutation-requires-exactly-one-identifier."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "realtime-log-config-mutation-requires-exactly-one-identifier"
GROUP = "error-semantics"
SERVICES = ["cloudfront"]


def _error(fn):
    """Call fn(); return its botocore (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"real AWS rejects this call, but it succeeded and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateRealtimeLogConfig and DeleteRealtimeLogConfig each reject naming neither Name nor
    ARN, and reject naming a Name and an ARN that resolve to different configs; a Name and ARN
    that agree, or either one alone, identify the config."""
    cf = ctx.client("cloudfront")

    # The role and stream need not exist for CloudFront to accept the config, but the role ARN
    # must sit in the caller's own account or PassRole raises a different, unrelated error.
    role_arn = f"arn:aws:iam::{ctx.account}:role/sim2real-rtlc-exactly1-role"
    stream_arn = f"arn:aws:kinesis:{ctx.region}:{ctx.account}:stream/sim2real-rtlc-exactly1-stream"
    endpoints = [{"StreamType": "Kinesis", "KinesisStreamConfig": {"RoleARN": role_arn, "StreamARN": stream_arn}}]

    name_a = ctx.unique_name("sim2real-rtlc-a-")
    name_b = ctx.unique_name("sim2real-rtlc-b-")

    created_a = cf.create_realtime_log_config(Name=name_a, EndPoints=endpoints, Fields=["timestamp"], SamplingRate=5)
    arn_a = created_a["RealtimeLogConfig"]["ARN"]
    ctx.on_cleanup(lambda: _delete_if_present(cf, name_a))

    created_b = cf.create_realtime_log_config(Name=name_b, EndPoints=endpoints, Fields=["c-ip"], SamplingRate=7)
    arn_b = created_b["RealtimeLogConfig"]["ARN"]
    ctx.on_cleanup(lambda: _delete_if_present(cf, name_b))

    # Neither identifier.
    u_neither_code, u_neither_message = _error(
        lambda: cf.update_realtime_log_config(Fields=["timestamp"], SamplingRate=5)
    )
    assert u_neither_code == "InvalidArgument", f"expected InvalidArgument for Update with no identifier, got {u_neither_code!r}"
    assert u_neither_message == "Invalid parameter received. Name/ARN", (
        f"expected AWS's exact message, got {u_neither_message!r}"
    )

    d_neither_code, d_neither_message = _error(lambda: cf.delete_realtime_log_config())
    assert d_neither_code == "InvalidArgument", f"expected InvalidArgument for Delete with no identifier, got {d_neither_code!r}"
    assert d_neither_message == "The parameter Name/ARN must be provided.", (
        f"expected AWS's exact message, got {d_neither_message!r}"
    )

    # A Name and ARN that resolve to different configs.
    u_mismatch_code, u_mismatch_message = _error(
        lambda: cf.update_realtime_log_config(Name=name_a, ARN=arn_b, Fields=["sc-status"], SamplingRate=42)
    )
    assert u_mismatch_code == "InvalidArgument", f"expected InvalidArgument for Update with conflicting identifiers, got {u_mismatch_code!r}"
    assert u_mismatch_message == "Invalid parameter received. Name/ARN", (
        f"expected AWS's exact message, got {u_mismatch_message!r}"
    )

    d_mismatch_code, d_mismatch_message = _error(lambda: cf.delete_realtime_log_config(Name=name_a, ARN=arn_b))
    assert d_mismatch_code == "InvalidArgument", f"expected InvalidArgument for Delete with conflicting identifiers, got {d_mismatch_code!r}"
    assert d_mismatch_message == "The parameter Name/ARN must refer to the same realtime log config.", (
        f"expected AWS's exact message, got {d_mismatch_message!r}"
    )

    # None of the rejected calls above touched either config.
    assert cf.get_realtime_log_config(Name=name_a)["RealtimeLogConfig"]["SamplingRate"] == 5, (
        "a rejected conflicting-identifier call must not change the Name-side config"
    )
    assert cf.get_realtime_log_config(Name=name_b)["RealtimeLogConfig"]["SamplingRate"] == 7, (
        "a rejected conflicting-identifier call must not change the ARN-side config"
    )

    # A Name and ARN that agree (both naming config "a") is accepted, not refused as "both".
    cf.update_realtime_log_config(Name=name_a, ARN=arn_a, Fields=["sc-status"], SamplingRate=55)
    agreeing = cf.get_realtime_log_config(Name=name_a)["RealtimeLogConfig"]
    assert agreeing["SamplingRate"] == 55, f"expected the agreeing-identifiers update to land, got {agreeing['SamplingRate']}"

    # ARN alone, with no Name at all, also identifies and mutates the config.
    cf.update_realtime_log_config(ARN=arn_b, Fields=["cs-uri-stem"], SamplingRate=77)
    by_arn = cf.get_realtime_log_config(Name=name_b)["RealtimeLogConfig"]
    assert by_arn["SamplingRate"] == 77, f"expected the ARN-only update to land, got {by_arn['SamplingRate']}"
    assert by_arn["Fields"] == ["cs-uri-stem"], f"expected Fields=['cs-uri-stem'], got {by_arn['Fields']!r}"

    # ARN alone, with no Name at all, also deletes.
    cf.delete_realtime_log_config(ARN=arn_b)
    gone_code, gone_message = _error(lambda: cf.get_realtime_log_config(Name=name_b))
    assert gone_code == "NoSuchRealtimeLogConfig", f"expected {name_b!r} gone after the ARN-only delete, got {gone_code!r}"
    assert gone_message == "The specified real-time log configuration does not exist.", (
        f"expected AWS's exact not-found message, got {gone_message!r}"
    )

    # name_a, deleted by agreeing Name and ARN together, is also gone afterward.
    cf.delete_realtime_log_config(Name=name_a, ARN=arn_a)
    final_code, _ = _error(lambda: cf.get_realtime_log_config(Name=name_a))
    assert final_code == "NoSuchRealtimeLogConfig", f"expected {name_a!r} gone after the agreeing-identifiers delete, got {final_code!r}"


def _delete_if_present(cf, name: str) -> None:
    try:
        cf.delete_realtime_log_config(Name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchRealtimeLogConfig":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
