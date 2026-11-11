"""delete-resource-policy-without-policy-not-found."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "delete-resource-policy-without-policy-not-found"
GROUP = "error-semantics"
SERVICES = ["comprehend"]

_NAME_PREFIX = "sim2real-drp-clf-"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteResourcePolicy and DescribeResourcePolicy on a never-created classifier ARN fail with
    ResourceNotFoundException and exact messages; on a real classifier without a policy both succeed,
    and a policy put there round-trips and is gone after delete."""
    comprehend = ctx.client("comprehend")
    account_id = _account_id(ctx)

    _sweep_orphaned_classifiers(comprehend)

    bucket, role_arn = _setup_bucket_and_role(ctx)
    _upload_training_csv(ctx, bucket)
    arn = _create_classifier(ctx, comprehend, bucket, role_arn)
    ctx.on_cleanup(lambda: comprehend.delete_document_classifier(DocumentClassifierArn=arn))

    # Stop training immediately -- before any assertion below could fail -- so the
    # classifier is already in a terminal state by the time cleanup's plain
    # DeleteDocumentClassifier call runs (it rejects a non-terminal classifier, and
    # cleanup callbacks are best-effort with no room for their own stop/poll loop).
    _stop_and_await_terminal(comprehend, arn)

    # A classifier ARN that was never created: THIS is where ResourceNotFoundException
    # actually lives, for both operations -- the contrast this CHECK is named for.
    fake_arn = arn.rsplit("/", 1)[0] + "/" + ctx.unique_name("does-not-exist-")
    del_code, message = _error(lambda: comprehend.delete_resource_policy(ResourceArn=fake_arn))
    assert del_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException deleting a policy on a nonexistent classifier, got {del_code!r}"
    )
    expected = "RESOURCE_NOT_FOUND: Could not find specified resource."
    assert message == expected, f"expected message {expected!r}, got {message!r}"
    desc_code, message = _error(lambda: comprehend.describe_resource_policy(ResourceArn=fake_arn))
    assert desc_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException describing a policy on a nonexistent classifier, got {desc_code!r}"
    )
    expected = "RESOURCE_NOT_FOUND: Could not find specified resource."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # No policy has ever been attached to the REAL classifier: neither call raises.
    comprehend.delete_resource_policy(ResourceArn=arn)
    pristine = comprehend.describe_resource_policy(ResourceArn=arn)
    assert "ResourcePolicy" not in pristine, (
        f"expected no ResourcePolicy key for a policy-less real classifier, got {pristine!r}"
    )

    # The classifier itself is unaffected -- an independent read at a different operation.
    described = comprehend.describe_document_classifier(DocumentClassifierArn=arn)
    described_arn = described["DocumentClassifierProperties"]["DocumentClassifierArn"]
    assert described_arn == arn, f"expected classifier to remain describable, got {described_arn!r}"

    # Positive control: attach a policy, confirm it round-trips, then delete it -- the
    # identical DeleteResourcePolicy call now deletes a policy that actually exists.
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "comprehend:ImportModel",
                "Resource": arn,
            }
        ],
    }
    comprehend.put_resource_policy(ResourceArn=arn, ResourcePolicy=json.dumps(policy))
    fetched = json.loads(comprehend.describe_resource_policy(ResourceArn=arn)["ResourcePolicy"])
    assert fetched == policy, f"expected the attached policy to round-trip, got {fetched!r}"

    comprehend.delete_resource_policy(ResourceArn=arn)

    # The delete actually took effect: an independent read is back to the pristine,
    # no-ResourcePolicy-key shape, exactly like before the policy was ever attached.
    after_delete = comprehend.describe_resource_policy(ResourceArn=arn)
    assert "ResourcePolicy" not in after_delete, (
        f"expected the policy to be gone after delete, got {after_delete!r}"
    )

    # And DeleteResourcePolicy on the now-policy-less classifier is, once again, a no-op.
    comprehend.delete_resource_policy(ResourceArn=arn)


def _error(fn):
    """Call fn(), which must fail; return its botocore error (code, message). An unexpected
    SUCCESS raises, so a target that accepts what AWS refuses is never read as a mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        error = exc.response["Error"]
        return error["Code"], error.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _account_id(ctx):
    return ctx.client("sts").get_caller_identity()["Account"]


def _sweep_orphaned_classifiers(comprehend) -> None:
    """Best-effort adoption cleanup, scoped to THIS check's own name prefix: an earlier,
    interrupted run of this check may have left a classifier whose IAM role and S3 bucket
    were already torn down (by cleanup, LIFO) before the classifier itself reached a
    terminal state, which is the only state DeleteDocumentClassifier will act on."""
    from botocore.exceptions import ClientError

    try:
        paginator = comprehend.get_paginator("list_document_classifiers")
        for page in paginator.paginate():
            for props in page.get("DocumentClassifierPropertiesList", []):
                arn = props["DocumentClassifierArn"]
                name = arn.rsplit("/", 1)[-1]
                if not name.startswith(_NAME_PREFIX):
                    continue
                status = props["Status"]
                if status in {"SUBMITTED", "TRAINING"}:
                    try:
                        comprehend.stop_training_document_classifier(DocumentClassifierArn=arn)
                    except ClientError:
                        pass
                    status = _poll_status_best_effort(comprehend, arn, timeout_s=30.0)
                if status in {"STOPPED", "TRAINED", "TRAINED_WITH_WARNING", "IN_ERROR"}:
                    try:
                        comprehend.delete_document_classifier(DocumentClassifierArn=arn)
                    except ClientError:
                        pass
    except ClientError:
        pass


def _poll_status_best_effort(comprehend, arn: str, timeout_s: float) -> str | None:
    terminal = {"STOPPED", "TRAINED", "TRAINED_WITH_WARNING", "IN_ERROR"}
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = comprehend.describe_document_classifier(DocumentClassifierArn=arn)[
            "DocumentClassifierProperties"
        ]["Status"]
        if status in terminal:
            return status
        time.sleep(5.0)
    return status


def _setup_bucket_and_role(ctx) -> tuple[str, str]:
    s3 = ctx.client("s3")
    iam = ctx.client("iam")

    bucket = ctx.unique_name("sim2real-comprehend-drp-").lower()
    if ctx.region == "us-east-1":
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
    policy_name = "sim2real-comprehend-drp-s3-access"
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(permission_policy))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))

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
    rows: list[str] = []
    for _ in range(4):
        for doc in positive_docs:
            rows.append(f"POSITIVE,{doc}")
        for doc in negative_docs:
            rows.append(f"NEGATIVE,{doc}")
    csv_body = "\n".join(rows) + "\n"
    s3.put_object(Bucket=bucket, Key="train.csv", Body=csv_body.encode("utf-8"))


def _create_classifier(ctx, comprehend, bucket: str, role_arn: str) -> str:
    """IAM role trust/permissions can take a few seconds to propagate to Comprehend."""
    name = ctx.unique_name(_NAME_PREFIX).replace("_", "-")

    def _create():
        return comprehend.create_document_classifier(
            DocumentClassifierName=name,
            DataAccessRoleArn=role_arn,
            LanguageCode="en",
            InputDataConfig={"S3Uri": f"s3://{bucket}/train.csv"},
            Tags=[{"Key": "sim2real", "Value": CHECK}],
        )

    deadline = time.monotonic() + 90.0
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return _create()["DocumentClassifierArn"]
        except Exception as exc:  # noqa: BLE001 - retry any validation failure until deadline
            last_exc = exc
            time.sleep(2)
    raise AssertionError(f"CreateDocumentClassifier never succeeded within 90s (last error: {last_exc!r})")


def _stop_and_await_terminal(comprehend, arn: str, timeout_s: float = 240.0) -> None:
    from botocore.exceptions import ClientError

    terminal = {"STOPPED", "TRAINED", "TRAINED_WITH_WARNING", "IN_ERROR"}
    deadline = time.monotonic() + timeout_s
    try:
        comprehend.stop_training_document_classifier(DocumentClassifierArn=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidRequestException":
            raise

    status = None
    while time.monotonic() < deadline:
        status = comprehend.describe_document_classifier(DocumentClassifierArn=arn)[
            "DocumentClassifierProperties"
        ]["Status"]
        if status in terminal:
            return
        time.sleep(2)
    raise AssertionError(f"classifier {arn} never reached a terminal state within {timeout_s}s (last={status!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
