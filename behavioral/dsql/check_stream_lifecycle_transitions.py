"""stream-lifecycle-transitions."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "stream-lifecycle-transitions"
GROUP = "state"
SERVICES = ["dsql"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateStream on an unknown cluster is refused ResourceNotFoundException, while on an ACTIVE
    cluster with a Kinesis target it reaches ACTIVE; after DeleteStream, GetStream and a second
    DeleteStream raise ResourceNotFoundException."""
    dsql = ctx.client("dsql")
    kinesis = ctx.client("kinesis")
    iam = ctx.client("iam")

    stream_name = ctx.unique_name("sim2real-dsql-kds-")
    kinesis.create_stream(
        StreamName=stream_name,
        StreamModeDetails={"StreamMode": "ON_DEMAND"},
        Tags={"sim2real-created-with": CHECK},
    )
    ctx.on_cleanup(lambda: _teardown(lambda: kinesis.delete_stream(StreamName=stream_name, EnforceConsumerDeletion=True)))
    kinesis.get_waiter("stream_exists").wait(StreamName=stream_name, WaiterConfig={"Delay": 2, "MaxAttempts": 90})
    kinesis_arn = kinesis.describe_stream_summary(StreamName=stream_name)["StreamDescriptionSummary"]["StreamARN"]

    role_name = ctx.unique_name("sim2real-dsql-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "dsql.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _teardown(lambda: iam.delete_role(RoleName=role_name)))
    permission_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": ["kinesis:PutRecord", "kinesis:PutRecords", "kinesis:DescribeStream",
                       "kinesis:DescribeStreamSummary", "kinesis:ListShards"],
            "Resource": kinesis_arn,
        }],
    }
    policy_name = "sim2real-dsql-kinesis-write"
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(permission_policy))
    ctx.on_cleanup(lambda: _teardown(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)))
    role_arn = iam.get_role(RoleName=role_name)["Role"]["Arn"]

    created_cluster = dsql.create_cluster(
        deletionProtectionEnabled=False, tags={"sim2real-created-with": CHECK}
    )
    cluster_id = created_cluster["identifier"]
    ctx.on_cleanup(lambda: _teardown(lambda: dsql.delete_cluster(identifier=cluster_id)))
    _wait_for_cluster_status(dsql, cluster_id, {"ACTIVE"}, timeout_s=180)

    # A well-formed but unknown cluster id: mutate the tail of the real generated id rather than
    # a hand-crafted uuid/hex string, since DSQL applies structural checks beyond the bare
    # character-class pattern (a hand-crafted string fails ValidationException instead of
    # reaching the ResourceNotFoundException path).
    alt_char = "a" if cluster_id[-1] != "a" else "b"
    fake_cluster_id = cluster_id[:-1] + alt_char
    target_definition = {"kinesis": {"streamArn": kinesis_arn, "roleArn": role_arn}}
    not_found_code, not_found_message = _error(lambda: dsql.create_stream(
        clusterIdentifier=fake_cluster_id, targetDefinition=target_definition,
        ordering="UNORDERED", format="JSON",
    ))
    assert not_found_code == "ResourceNotFoundException", not_found_code
    fake_cluster_arn = created_cluster["arn"].rsplit("/", 1)[0] + "/" + fake_cluster_id
    assert not_found_message == (
        f"The resource with ARN {fake_cluster_arn} doesn't exist. Verify the ARN and try again."
    ), not_found_message


    stream_created = _retry_on_access_denied(
        lambda: dsql.create_stream(
            clusterIdentifier=cluster_id, targetDefinition=target_definition,
            ordering="UNORDERED", format="JSON", tags={"sim2real-created-with": CHECK},
        ),
        timeout_s=90,
    )
    stream_id = stream_created["streamIdentifier"]
    ctx.on_cleanup(lambda: _teardown(lambda: dsql.delete_stream(clusterIdentifier=cluster_id, streamIdentifier=stream_id)))
    assert stream_created["ordering"] == "UNORDERED", stream_created["ordering"]
    assert stream_created["format"] == "JSON", stream_created["format"]

    active_stream = _wait_for_stream_status(dsql, cluster_id, stream_id, {"ACTIVE"}, timeout_s=240)
    assert active_stream["status"] == "ACTIVE", active_stream["status"]

    dsql.delete_stream(clusterIdentifier=cluster_id, streamIdentifier=stream_id)
    _wait_for_stream_not_found(dsql, cluster_id, stream_id, timeout_s=180)

    # The delete does not just make the stream disappear from reads — a further mutation
    # against the now-dead stream id is rejected too, not silently accepted.
    redelete_code, redelete_message = _error(lambda: dsql.delete_stream(clusterIdentifier=cluster_id, streamIdentifier=stream_id))
    assert redelete_code == "ResourceNotFoundException", redelete_code
    assert redelete_message == (
        f"The resource with ARN {created_cluster['arn']}/stream/{stream_id} doesn't exist. "
        "Verify the ARN and try again."
    ), redelete_message


# ===== helpers =====

def _error(fn):
    """Call fn() and return its ClientError (code, message). An unexpected SUCCESS raises rather
    than reading as a mere code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _retry_on_access_denied(fn, timeout_s=90.0, interval_s=5.0):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as err:
            code = err.response["Error"]["Code"]
            message = err.response["Error"].get("Message", "")
            retryable = code == "AccessDeniedException" or (
                code == "ValidationException" and "can't access the specified IAM role" in message
            )
            if not retryable or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _wait_for_cluster_status(dsql, identifier, target_statuses, timeout_s=180.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = dsql.get_cluster(identifier=identifier)
        if last["status"] in target_statuses:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"cluster never reached {target_statuses}, last={last}")


def _wait_for_stream_status(dsql, cluster_id, stream_id, target_statuses, timeout_s=240.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = dsql.get_stream(clusterIdentifier=cluster_id, streamIdentifier=stream_id)
        if last["status"] in target_statuses:
            return last
        if last["status"] == "FAILED" and "FAILED" not in target_statuses:
            raise AssertionError(f"stream unexpectedly reached FAILED: {last}")
        time.sleep(interval_s)
    raise AssertionError(f"stream never reached {target_statuses}, last={last}")


def _wait_for_stream_not_found(dsql, cluster_id, stream_id, timeout_s=180.0, interval_s=5.0):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            dsql.get_stream(clusterIdentifier=cluster_id, streamIdentifier=stream_id)
        except ClientError as err:
            if err.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(interval_s)
    raise AssertionError(f"stream {stream_id} never disappeared")


# Teardown codes: already gone (DSQL / Kinesis, IAM), or still settling (a stream or cluster
# mid-transition refuses its delete until it settles).
_GONE = frozenset({"ResourceNotFoundException", "NoSuchEntity"})
_BUSY = frozenset({"ConflictException", "ResourceInUseException"})


def _teardown(fn, timeout_s=120.0):
    """Run one teardown call: a resource already gone is fine; one still settling is retried every
    2 s up to timeout_s; any other error raises."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code in _GONE:
                return
            if code not in _BUSY or time.monotonic() >= deadline:
                raise
        time.sleep(2)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
