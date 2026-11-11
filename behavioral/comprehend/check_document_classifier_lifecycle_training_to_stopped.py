"""document-classifier-lifecycle-training-to-stopped."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "document-classifier-lifecycle-training-to-stopped"
GROUP = "lifecycle"
SERVICES = ["comprehend"]
_NOT_FOUND_MESSAGE = "RESOURCE_NOT_FOUND: Could not find specified resource."


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A real classifier walks SUBMITTED->TRAINING, is stopped to STOPPED, and tags round-trip on it."""
    bucket, role_arn = _setup_bucket_and_role(ctx)
    _upload_training_csv(ctx, bucket)

    comprehend = ctx.client("comprehend")
    arn, seen_statuses, last_message = _create_classifier_until_training(ctx, comprehend, bucket, role_arn)
    ctx.on_cleanup(lambda: _delete_classifier(ctx, arn))

    # 1) A nonexistent classifier ARN is rejected -- distinct from the real one below.
    fake_arn = arn.rsplit("/", 1)[0] + "/does-not-exist-0000"
    try:
        comprehend.describe_document_classifier(DocumentClassifierArn=fake_arn)
        raise AssertionError("expected ResourceNotFoundException for a nonexistent classifier ARN")
    except comprehend.exceptions.ResourceNotFoundException as exc:
        message = exc.response["Error"].get("Message")
        assert message == _NOT_FOUND_MESSAGE, message

    # 2) SUBMITTED -> TRAINING was already observed while creating the classifier above.
    assert "TRAINING" in seen_statuses or seen_statuses[-1] in {
        "TRAINED",
        "TRAINED_WITH_WARNING",
    }, f"expected to observe TRAINING, saw {seen_statuses!r} (message={last_message!r})"

    # 3) Tag round trip on the live resource.
    comprehend.tag_resource(ResourceArn=arn, Tags=[{"Key": "sim2real", "Value": "yes"}])
    tags = comprehend.list_tags_for_resource(ResourceArn=arn)["Tags"]
    assert {"Key": "sim2real", "Value": "yes"} in tags, tags
    comprehend.untag_resource(ResourceArn=arn, TagKeys=["sim2real"])
    tags_after = comprehend.list_tags_for_resource(ResourceArn=arn)["Tags"]
    assert all(t["Key"] != "sim2real" for t in tags_after), tags_after

    # 4) Stop training and observe the STOPPED terminal state.
    comprehend.stop_training_document_classifier(DocumentClassifierArn=arn)
    final_status = _poll_until_terminal(ctx, arn, timeout_s=360)
    assert final_status == "STOPPED", f"expected STOPPED after stop request, got {final_status!r}"

    # 5) Delete proves gone and unusable: an independent read 404s, and a further mutation on the
    # same dead id fails with the same specific error -- not just the delete call's own response.
    comprehend.delete_document_classifier(DocumentClassifierArn=arn)
    _poll_until_deleted(ctx, arn, timeout_s=120)
    try:
        comprehend.tag_resource(ResourceArn=arn, Tags=[{"Key": "sim2real-post-delete", "Value": "x"}])
        raise AssertionError("expected ResourceNotFoundException tagging a deleted classifier")
    except comprehend.exceptions.ResourceNotFoundException as exc:
        message = exc.response["Error"].get("Message")
        assert message == _NOT_FOUND_MESSAGE, message


# ===== helpers =====


def _retry_role_propagation(fn, timeout_s: float = 90.0, interval_s: float = 6.0):
    """IAM role trust/permissions can take a few seconds to propagate to Comprehend."""
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except Exception as exc:  # noqa: BLE001 - retry any validation failure until deadline
            last_exc = exc
            time.sleep(interval_s)
    raise AssertionError(f"operation never succeeded within {timeout_s}s (last error: {last_exc!r})")


def _create_classifier_until_training(ctx, comprehend, bucket: str, role_arn: str, max_attempts: int = 4):
    """A freshly-propagated IAM role can lose the race with CreateDocumentClassifier: the call
    itself validates the role ARN synchronously and succeeds, but Comprehend's own read of the
    training data happens moments later and can still see a stale (pre-propagation) IAM view,
    failing IN_ERROR with NO_READ_ACCESS_TO_INPUT. That is IAM eventual consistency, not a real
    permissions defect -- recreate with a fresh classifier name and back off, bounded."""
    last_seen, last_message = None, None
    for attempt in range(max_attempts):
        name = ctx.unique_name("sim2real-clf-").replace("_", "-")

        def _create():
            return comprehend.create_document_classifier(
                DocumentClassifierName=name,
                DataAccessRoleArn=role_arn,
                LanguageCode="en",
                InputDataConfig={"S3Uri": f"s3://{bucket}/train.csv"},
            )

        arn = _retry_role_propagation(_create)["DocumentClassifierArn"]
        seen, message = _poll_until_status_in(
            ctx, arn, {"TRAINING", "TRAINED", "TRAINED_WITH_WARNING", "IN_ERROR", "STOPPED"}, timeout_s=360
        )
        if "TRAINING" in seen or seen[-1] in {"TRAINED", "TRAINED_WITH_WARNING"}:
            return arn, seen, message
        last_seen, last_message = seen, message
        is_role_propagation_race = seen[-1] == "IN_ERROR" and message and "NO_READ_ACCESS_TO_INPUT" in message
        comprehend.delete_document_classifier(DocumentClassifierArn=arn)
        if not is_role_propagation_race or attempt == max_attempts - 1:
            break
        time.sleep(20 * (attempt + 1))
    raise AssertionError(
        f"classifier never reached TRAINING within {max_attempts} attempt(s), "
        f"saw {last_seen!r} (message={last_message!r})"
    )


def _poll_until_status_in(ctx, classifier_arn: str, terminal_or_training: set, timeout_s: float):
    comprehend = ctx.client("comprehend")
    seen = []
    message = None
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        props = comprehend.describe_document_classifier(DocumentClassifierArn=classifier_arn)[
            "DocumentClassifierProperties"
        ]
        status = props["Status"]
        message = props.get("Message")
        if not seen or seen[-1] != status:
            seen.append(status)
        if status in terminal_or_training:
            return seen, message
        time.sleep(2)
    raise AssertionError(f"classifier never reached {terminal_or_training!r} within {timeout_s}s: saw {seen!r}")


def _poll_until_terminal(ctx, classifier_arn: str, timeout_s: float):
    comprehend = ctx.client("comprehend")
    terminal = {"STOPPED", "TRAINED", "TRAINED_WITH_WARNING", "IN_ERROR"}
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = comprehend.describe_document_classifier(DocumentClassifierArn=classifier_arn)[
            "DocumentClassifierProperties"
        ]["Status"]
        if status in terminal:
            return status
        time.sleep(2)
    raise AssertionError(f"classifier never reached a terminal state within {timeout_s}s (last={status!r})")


def _poll_until_deleted(ctx, classifier_arn: str, timeout_s: float) -> None:
    """DeleteDocumentClassifier is asynchronous; poll describe until it 404s."""
    comprehend = ctx.client("comprehend")
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        try:
            last_status = comprehend.describe_document_classifier(DocumentClassifierArn=classifier_arn)[
                "DocumentClassifierProperties"
            ]["Status"]
        except comprehend.exceptions.ResourceNotFoundException:
            return
        time.sleep(5)
    raise AssertionError(f"classifier not deleted within {timeout_s}s (last status={last_status!r})")


def _delete_classifier(ctx, classifier_arn: str) -> None:
    """Teardown: stop a classifier still training, wait for a terminal state, then delete; only not-found is tolerated."""
    comprehend = ctx.client("comprehend")
    try:
        comprehend.stop_training_document_classifier(DocumentClassifierArn=classifier_arn)
    except comprehend.exceptions.ResourceNotFoundException:
        return
    except comprehend.exceptions.InvalidRequestException:
        pass  # already stopping or terminal; the poll below raises unless it reaches a terminal state
    try:
        _poll_until_terminal(ctx, classifier_arn, timeout_s=360)
        comprehend.delete_document_classifier(DocumentClassifierArn=classifier_arn)
    except comprehend.exceptions.ResourceNotFoundException:
        return


def _setup_bucket_and_role(ctx) -> tuple[str, str]:
    s3 = ctx.client("s3")
    iam = ctx.client("iam")
    sts = ctx.client("sts")

    bucket = ctx.unique_name("sim2real-comprehend-").lower()
    if ctx.region == "us-east-1":
        # us-east-1 is an S3 API quirk, not a hardcoded target: CreateBucket rejects an explicit
        # LocationConstraint there, so ctx.region still drives which branch runs.
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket))

    role_name = ctx.unique_name("sim2real-comprehend-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "comprehend.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy))
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    permission_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:ListBucket", "s3:PutObject"],
                "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
            }
        ],
    }
    policy_name = "sim2real-comprehend-s3-access"
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(permission_policy))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))

    _ = sts  # not otherwise used here; kept for parity with sibling checks
    return bucket, role_arn


def _empty_and_delete_bucket(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket):
        objects = [{"Key": obj["Key"]} for obj in page.get("Contents", [])]
        if objects:
            failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": objects}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    s3.delete_bucket(Bucket=bucket)


def _upload_training_csv(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    rows: list[str] = []
    positive_docs = [
        "This product exceeded my expectations and works flawlessly every day",
        "Absolutely fantastic purchase, I would buy this again in a heartbeat",
        "Great value for the price and the quality is outstanding overall",
        "I am so happy with this item, it works perfectly and looks great",
        "Excellent build quality and the customer support was very helpful",
    ]
    negative_docs = [
        "This product broke after one day and the support team never replied",
        "Terrible quality, it stopped working within a week of purchase",
        "I regret buying this, it is flimsy and does not work as advertised",
        "Very disappointed with the build quality and the slow shipping",
        "Waste of money, it arrived damaged and customer service ignored me",
    ]
    for _ in range(4):
        for doc in positive_docs:
            rows.append(f"POSITIVE,{doc}")
        for doc in negative_docs:
            rows.append(f"NEGATIVE,{doc}")
    csv_body = "\n".join(rows) + "\n"
    s3.put_object(Bucket=bucket, Key="train.csv", Body=csv_body.encode("utf-8"))


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
