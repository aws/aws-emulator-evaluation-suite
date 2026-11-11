"""put-model-package-group-policy-concurrent-overwrite-deterministic."""
from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-model-package-group-policy-concurrent-overwrite-deterministic"
GROUP = "concurrency"
SERVICES = ["sagemaker"]

_WRITER_COUNT = 8
_RETRY_DEADLINE_S = 30.0


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Concurrent PutModelPackageGroupPolicy writes on one group converge to exactly one writer's
    full policy, never a merge; writers retry SageMaker's InflightPolicy ValidationException until
    their write lands."""
    sm = ctx.client("sagemaker")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    group_name = ctx.unique_name("sim2real-mpg-")

    group_arn = sm.create_model_package_group(ModelPackageGroupName=group_name)[
        "ModelPackageGroupArn"
    ]
    ctx.on_cleanup(lambda: _delete_group(sm, group_name))

    def _policy_for(i: int) -> dict:
        return {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": f"sim2real-writer-{i}",
                    "Effect": "Allow",
                    "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                    "Action": "sagemaker:DescribeModelPackageGroup",
                    "Resource": group_arn,
                }
            ],
        }

    def _put(i: int) -> int:
        from botocore.exceptions import ClientError

        deadline = time.monotonic() + _RETRY_DEADLINE_S
        while True:
            try:
                sm.put_model_package_group_policy(
                    ModelPackageGroupName=group_name,
                    ResourcePolicy=json.dumps(_policy_for(i)),
                )
                return i
            except ClientError as exc:
                err = exc.response["Error"]
                if err["Code"] == "ValidationException" and "InflightPolicy" in err.get(
                    "Message", ""
                ):
                    # Real SageMaker serializes concurrent PutModelPackageGroupPolicy
                    # calls with an optimistic lock: a racer that lands while another
                    # write is still in-flight is rejected with this specific
                    # transient error, not merged/corrupted. Retry until it lands.
                    if time.monotonic() >= deadline:
                        raise
                    time.sleep(0.5)
                    continue
                raise

    with ThreadPoolExecutor(max_workers=_WRITER_COUNT) as pool:
        futures = [pool.submit(_put, i) for i in range(_WRITER_COUNT)]
        for future in as_completed(futures):
            future.result()  # propagate any unexpected exception

    final = sm.get_model_package_group_policy(ModelPackageGroupName=group_name)
    final_doc = json.loads(final["ResourcePolicy"])
    statements = final_doc["Statement"]
    assert len(statements) == 1, f"policy is corrupted/merged: {final_doc}"

    winning_sid = statements[0]["Sid"]
    assert winning_sid.startswith("sim2real-writer-"), f"unrecognized Sid: {winning_sid!r}"
    winner_index = int(winning_sid.rsplit("-", 1)[1])
    assert 0 <= winner_index < _WRITER_COUNT, (
        f"winner index {winner_index} outside the {_WRITER_COUNT} submitted writers"
    )

    # AWS re-serializes the stored document into its own canonical form (reordered
    # top-level keys, no incidental whitespace), so raw string equality does not
    # hold -- compare the parsed document instead. It must be semantically
    # identical, field for field, to the winner's exact submission, not a hybrid.
    assert final_doc == _policy_for(winner_index), (
        f"stored policy is not semantically identical to writer {winner_index}'s "
        f"submission: {final_doc}"
    )


def _delete_group(sm, name: str) -> None:
    _delete_if_present(lambda: sm.delete_model_package_group_policy(ModelPackageGroupName=name))
    _delete_if_present(lambda: sm.delete_model_package_group(ModelPackageGroupName=name))


_GONE_MARKERS = ("does not exist", "not found", "cannot find")


def _delete_if_present(fn) -> None:
    """Teardown delete: returns when SageMaker reports the resource is already gone and
    raises any other failure."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response["Error"]
        message = err.get("Message", "").lower()
        gone = err["Code"] == "ResourceNotFound" or (
            err["Code"] == "ValidationException" and any(m in message for m in _GONE_MARKERS)
        )
        if not gone:
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
