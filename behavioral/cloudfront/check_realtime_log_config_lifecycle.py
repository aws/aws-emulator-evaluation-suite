"""realtime-log-config-lifecycle."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "realtime-log-config-lifecycle"
GROUP = "state-machine"
SERVICES = ["cloudfront"]


def _create_kinesis_stream(ctx) -> str:
    kinesis = ctx.client("kinesis")
    name = ctx.unique_name("sim2real-rtlc-stream-")
    kinesis.create_stream(
        StreamName=name,
        StreamModeDetails={"StreamMode": "ON_DEMAND"},
        Tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(lambda: kinesis.delete_stream(StreamName=name))
    deadline = time.monotonic() + 90.0
    while time.monotonic() < deadline:
        desc = kinesis.describe_stream(StreamName=name)["StreamDescription"]
        if desc["StreamStatus"] == "ACTIVE":
            return desc["StreamARN"]
        time.sleep(3.0)
    raise TimeoutError(f"kinesis stream {name!r} did not reach ACTIVE within 90s")


def _create_role(ctx) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-rtlc-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "cloudfront.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": ["kinesis:PutRecord", "kinesis:PutRecords"], "Resource": "*"}
        ],
    }
    iam.put_role_policy(
        RoleName=name, PolicyName="sim2real-rtlc-kinesis", PolicyDocument=json.dumps(policy)
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=name, PolicyName="sim2real-rtlc-kinesis"))
    return role["Arn"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Real-time log config create->get->update->delete lifecycle and disappearance from
    list, wired to a real Kinesis stream and IAM role."""
    stream_arn = _create_kinesis_stream(ctx)
    role_arn = _create_role(ctx)
    cf = ctx.client("cloudfront")
    name = ctx.unique_name("sim2real-rtlc-")

    def _endpoints(role: str) -> list[dict]:
        return [
            {
                "StreamType": "Kinesis",
                "KinesisStreamConfig": {"RoleARN": role, "StreamARN": stream_arn},
            }
        ]

    created = cf.create_realtime_log_config(
        Name=name,
        EndPoints=_endpoints(role_arn),
        Fields=["timestamp", "c-ip", "cs-method"],
        SamplingRate=50,
    )
    cfg_arn = created["RealtimeLogConfig"]["ARN"]
    assert created["RealtimeLogConfig"]["SamplingRate"] == 50, (
        f"expected SamplingRate=50 on create, got {created['RealtimeLogConfig']['SamplingRate']!r}"
    )
    assert created["RealtimeLogConfig"]["Fields"] == ["timestamp", "c-ip", "cs-method"], (
        f"expected Fields echoed back, got {created['RealtimeLogConfig']['Fields']!r}"
    )

    ctx.on_cleanup(lambda: _delete_realtime_log_config_if_present(cf, cfg_arn))

    got = cf.get_realtime_log_config(ARN=cfg_arn)
    assert got["RealtimeLogConfig"]["Name"] == name, (
        f"expected Name={name!r} on get, got {got['RealtimeLogConfig']['Name']!r}"
    )
    assert got["RealtimeLogConfig"]["EndPoints"][0]["KinesisStreamConfig"]["StreamARN"] == stream_arn, (
        f"expected StreamARN={stream_arn!r} on get, got "
        f"{got['RealtimeLogConfig']['EndPoints'][0]['KinesisStreamConfig']['StreamARN']!r}"
    )

    listing = cf.list_realtime_log_configs()
    names = [
        i["Name"] for i in listing.get("RealtimeLogConfigs", {}).get("Items", []) or []
    ]
    assert name in names, f"expected {name!r} in list_realtime_log_configs, got {names!r}"

    updated = cf.update_realtime_log_config(ARN=cfg_arn, SamplingRate=100)
    assert updated["RealtimeLogConfig"]["SamplingRate"] == 100, (
        f"expected SamplingRate=100 after update, got {updated['RealtimeLogConfig']['SamplingRate']!r}"
    )
    assert updated["RealtimeLogConfig"]["Name"] == name, (
        f"expected Name={name!r} unchanged after update, got {updated['RealtimeLogConfig']['Name']!r}"
    )

    cf.delete_realtime_log_config(ARN=cfg_arn)

    code, message = _error(lambda: cf.get_realtime_log_config(ARN=cfg_arn))
    assert code == "NoSuchRealtimeLogConfig", f"expected 404 NoSuch..., got {code!r}"
    expected = "The specified real-time log configuration does not exist."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # A mutation on the dead id also fails, not just a read.
    code_mutation, message_mutation = _error(
        lambda: cf.update_realtime_log_config(ARN=cfg_arn, SamplingRate=1)
    )
    assert code_mutation == "NoSuchRealtimeLogConfig", (
        f"expected update on deleted config to fail NoSuchRealtimeLogConfig, got {code_mutation!r}"
    )
    expected_mutation = "The specified real-time log configuration does not exist."
    assert message_mutation == expected_mutation, (
        f"expected message {expected_mutation!r}, got {message_mutation!r}"
    )

    listing2 = cf.list_realtime_log_configs()
    names2 = [
        i["Name"] for i in listing2.get("RealtimeLogConfigs", {}).get("Items", []) or []
    ]
    assert name not in names2, f"expected {name!r} absent from list after delete, got {names2!r}"


def _delete_realtime_log_config_if_present(cf, cfg_arn: str) -> None:
    """Teardown; a config the check itself already deleted is left alone."""
    try:
        cf.delete_realtime_log_config(ARN=cfg_arn)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NoSuchRealtimeLogConfig":
            raise


def _error(fn):
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
