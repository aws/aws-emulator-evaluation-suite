"""tag-resource-concurrent-modification-conflict."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "tag-resource-concurrent-modification-conflict"
GROUP = "concurrency"
SERVICES = ["cloudwatch"]


def _error_code(exc) -> str:
    return exc.response["Error"]["Code"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Concurrent TagResource calls on one alarm, retried on ConcurrentModificationException or
    ConflictException, leave the full union of tags; concurrent removes and updates leave the
    removed keys gone and the updated values set."""
    from botocore.exceptions import ClientError

    cw = ctx.client("cloudwatch")

    alarm_name = ctx.unique_name("sim2real-behav-tag-alarm-")
    cw.put_metric_alarm(
        AlarmName=alarm_name,
        Namespace=ctx.unique_name("Sim2RealBehavTagNS"),
        MetricName="RequestCount",
        Statistic="Sum",
        Period=60,
        EvaluationPeriods=1,
        Threshold=1.0,
        ComparisonOperator="GreaterThanThreshold",
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[alarm_name]))
    alarm_arn = cw.describe_alarms(AlarmNames=[alarm_name])["MetricAlarms"][0]["AlarmArn"]

    allowed_conflict_codes = {"ConcurrentModificationException", "ConflictException"}
    n_workers = 12
    expected_tags = {f"sim2real-behav-key-{i}": f"value-{i}" for i in range(n_workers)}

    def _tag_with_retry(key, value, attempts=6):
        for _ in range(attempts):
            try:
                cw.tag_resource(ResourceARN=alarm_arn, Tags=[{"Key": key, "Value": value}])
                return None
            except ClientError as exc:
                code = _error_code(exc)
                if code not in allowed_conflict_codes:
                    return code
        return "exhausted-retries"

    with ThreadPoolExecutor(max_workers=n_workers) as pool:
        results = list(pool.map(lambda kv: _tag_with_retry(*kv), expected_tags.items()))

    unexpected = [r for r in results if r is not None]
    assert not unexpected, f"tagging failed with unexpected/unrecoverable outcomes: {unexpected}"

    tags = {t["Key"]: t["Value"] for t in cw.list_tags_for_resource(ResourceARN=alarm_arn)["Tags"]}
    for key, value in expected_tags.items():
        assert tags.get(key) == value, f"tag {key!r} missing or wrong after concurrent tagging: {tags.get(key)!r}"

    # Now race UntagResource for half the keys concurrently with TagResource updates to the other
    # half, and verify the final state exactly reflects the net effect of both operations.
    keys_to_remove = list(expected_tags.keys())[: n_workers // 2]
    keys_to_update = list(expected_tags.keys())[n_workers // 2 :]

    def _untag_with_retry(key, attempts=6):
        for _ in range(attempts):
            try:
                cw.untag_resource(ResourceARN=alarm_arn, TagKeys=[key])
                return None
            except ClientError as exc:
                code = _error_code(exc)
                if code not in allowed_conflict_codes:
                    return code
        return "exhausted-retries"

    def _retag_with_retry(key, attempts=6):
        return _tag_with_retry(key, expected_tags[key] + "-updated", attempts=attempts)

    with ThreadPoolExecutor(max_workers=n_workers) as pool:
        remove_futures = [pool.submit(_untag_with_retry, k) for k in keys_to_remove]
        update_futures = [pool.submit(_retag_with_retry, k) for k in keys_to_update]
        remove_results = [f.result() for f in remove_futures]
        update_results = [f.result() for f in update_futures]

    assert not [r for r in remove_results if r is not None], remove_results
    assert not [r for r in update_results if r is not None], update_results

    final_tags = {t["Key"]: t["Value"] for t in cw.list_tags_for_resource(ResourceARN=alarm_arn)["Tags"]}
    for key in keys_to_remove:
        assert key not in final_tags, f"tag {key!r} should have been removed but is still present"
    for key in keys_to_update:
        assert final_tags.get(key) == expected_tags[key] + "-updated", (
            f"tag {key!r} was not updated correctly: {final_tags.get(key)!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
