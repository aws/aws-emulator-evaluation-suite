"""op-contract-get-realtime-log-config-name-and-arn-mutually-exclusive-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-get-realtime-log-config-name-and-arn-mutually-exclusive-rejected"
GROUP = "error-semantics"
SERVICES = ["cloudfront"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetRealtimeLogConfig with neither Name nor ARN is InvalidArgument; with both, Name wins and
    ARN is disregarded, even when the ARN belongs to a different config."""
    cf = ctx.client("cloudfront")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    name = ctx.unique_name("sim2real-rtlc-excl-")
    other_name = ctx.unique_name("sim2real-rtlc-excl-other-")
    # The role/stream need not exist, but PassRole still applies, so the role ARN must be in
    # the caller's own account to avoid an unrelated cross-account AccessDenied.
    role_arn = f"arn:aws:iam::{account_id}:role/sim2real-behavioral-test-role"
    stream_arn = f"arn:aws:kinesis:{ctx.region}:{account_id}:stream/sim2real-behavioral-test-stream"

    def _endpoints() -> list[dict]:
        return [{"StreamType": "Kinesis", "KinesisStreamConfig": {"RoleARN": role_arn, "StreamARN": stream_arn}}]

    created = cf.create_realtime_log_config(
        Name=name, EndPoints=_endpoints(), Fields=["timestamp"], SamplingRate=10
    )
    config_arn = created["RealtimeLogConfig"]["ARN"]
    ctx.on_cleanup(lambda: cf.delete_realtime_log_config(Name=name))

    other = cf.create_realtime_log_config(
        Name=other_name, EndPoints=_endpoints(), Fields=["cs-method"], SamplingRate=20
    )
    other_arn = other["RealtimeLogConfig"]["ARN"]
    ctx.on_cleanup(lambda: cf.delete_realtime_log_config(Name=other_name))

    both_resp = cf.get_realtime_log_config(Name=name, ARN=config_arn)
    assert both_resp["RealtimeLogConfig"]["Name"] == name
    assert both_resp["RealtimeLogConfig"]["ARN"] == config_arn

    mismatched_resp = cf.get_realtime_log_config(Name=name, ARN=other_arn)
    got = mismatched_resp["RealtimeLogConfig"]
    assert got["Name"] == name, f"expected Name to win resolution, got {got['Name']!r}"
    assert got["ARN"] == config_arn, f"expected {config_arn}, got {got['ARN']!r} (resolved by ARN, not Name)"
    assert got["SamplingRate"] == 10, f"expected the config named {name!r} (rate 10), got {got}"

    neither_code, neither_message = _error(lambda: cf.get_realtime_log_config())
    assert neither_code == "InvalidArgument", f"expected InvalidArgument for neither Name nor ARN, got {neither_code}"
    assert neither_message == "The parameter Name/ARN must be provided.", (
        f"expected AWS's exact missing-identifier message, got {neither_message!r}"
    )


def _error(fn):
    """Call fn() and return its botocore error (code, message); an unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
