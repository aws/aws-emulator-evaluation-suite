"""op-contract-createRealtimeLogConfig."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-createRealtimeLogConfig"
GROUP = "error-semantics"
SERVICES = ["cloudfront"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateRealtimeLogConfig stores the config without validating stream/role existence
    (delivery-time concern, not create-time); a duplicate Name is rejected without mutating the
    original, and the Name becomes reusable only once the original is deleted."""
    cf = ctx.client("cloudfront")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    name = ctx.unique_name("sim2real-rtlog-")
    role_arn = f"arn:aws:iam::{account_id}:role/sim2real-nonexistent-role"
    stream_arn = f"arn:aws:kinesis:{ctx.region}:{account_id}:stream/sim2real-nonexistent-stream"

    def _create(sampling_rate, fields):
        return cf.create_realtime_log_config(
            Name=name,
            SamplingRate=sampling_rate,
            Fields=fields,
            EndPoints=[
                {
                    "StreamType": "Kinesis",
                    "KinesisStreamConfig": {"RoleARN": role_arn, "StreamARN": stream_arn},
                }
            ],
        )

    resp = _create(50, ["timestamp", "c-ip", "sc-status"])
    cfg = resp["RealtimeLogConfig"]
    ctx.on_cleanup(lambda: _delete_config(ctx, name))

    assert cfg["Name"] == name, f"expected Name {name!r}, got {cfg['Name']!r}"
    assert cfg["SamplingRate"] == 50, f"expected SamplingRate 50, got {cfg['SamplingRate']!r}"
    assert cfg["Fields"] == ["timestamp", "c-ip", "sc-status"], (
        f"expected the requested Fields, got {cfg['Fields']!r}"
    )
    assert cfg["EndPoints"][0]["KinesisStreamConfig"]["StreamARN"] == stream_arn, (
        "expected the nonexistent StreamARN to be stored as-is (validated at delivery time, not "
        f"create time), got {cfg['EndPoints'][0]['KinesisStreamConfig']['StreamARN']!r}"
    )
    assert cfg["ARN"].endswith(name), f"expected the config ARN to end with {name!r}, got {cfg['ARN']!r}"

    got = cf.get_realtime_log_config(Name=name)["RealtimeLogConfig"]
    assert got["ARN"] == cfg["ARN"], f"expected an independent read to see ARN {cfg['ARN']!r}, got {got['ARN']!r}"

    # Positive control established above. Break exactly one thing: reuse the Name.
    code, message = _error(lambda: _create(100, ["timestamp"]))
    assert code == "RealtimeLogConfigAlreadyExists", f"expected RealtimeLogConfigAlreadyExists, got {code}"
    expected = "A real-time log configuration with this name already exists."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: the rejected duplicate must not have mutated the original, via an
    # independent read.
    unmutated = cf.get_realtime_log_config(Name=name)["RealtimeLogConfig"]
    assert unmutated["SamplingRate"] == 50, (
        f"expected the rejected duplicate to leave SamplingRate at 50, got {unmutated['SamplingRate']!r}"
    )
    assert unmutated["Fields"] == ["timestamp", "c-ip", "sc-status"], (
        f"expected the rejected duplicate to leave Fields unchanged, got {unmutated['Fields']!r}"
    )

    # Restore: delete the original, freeing the Name.
    cf.delete_realtime_log_config(Name=name)

    gone_code, gone_message = _error(lambda: cf.get_realtime_log_config(Name=name))
    assert gone_code == "NoSuchRealtimeLogConfig", f"expected NoSuchRealtimeLogConfig after delete, got {gone_code}"
    expected = "The specified real-time log configuration does not exist."
    assert gone_message == expected, f"expected message {expected!r}, got {gone_message!r}"

    mutate_code, mutate_message = _error(
        lambda: cf.update_realtime_log_config(
            Name=name,
            SamplingRate=10,
            Fields=["timestamp"],
            EndPoints=[
                {
                    "StreamType": "Kinesis",
                    "KinesisStreamConfig": {"RoleARN": role_arn, "StreamARN": stream_arn},
                }
            ],
        )
    )
    assert mutate_code == "NoSuchRealtimeLogConfig", (
        f"expected a mutation on the deleted Name to fail NoSuchRealtimeLogConfig, got {mutate_code}"
    )
    expected = "The specified real-time log configuration does not exist."
    assert mutate_message == expected, f"expected message {expected!r}, got {mutate_message!r}"

    # The identical call rejected earlier as a duplicate now succeeds: the Name is reusable.
    resp2 = _create(100, ["timestamp"])
    cfg2 = resp2["RealtimeLogConfig"]
    ctx.on_cleanup(lambda: _delete_config(ctx, name))
    assert cfg2["SamplingRate"] == 100, (
        f"expected the reused Name to accept SamplingRate 100, got {cfg2['SamplingRate']!r}"
    )

    got2 = cf.get_realtime_log_config(Name=name)["RealtimeLogConfig"]
    assert got2["ARN"] == cfg2["ARN"], (
        f"expected an independent read to see the recreated ARN {cfg2['ARN']!r}, got {got2['ARN']!r}"
    )


def _delete_config(ctx, name: str) -> None:
    cf = ctx.client("cloudfront")
    try:
        cf.delete_realtime_log_config(Name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchRealtimeLogConfig":
            raise


def _error(fn):
    """Call fn(); return the ClientError (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
