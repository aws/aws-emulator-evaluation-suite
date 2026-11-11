"""concurrent-generated-template-limit."""
from __future__ import annotations

import random
import time
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-generated-template-limit"
GROUP = "concurrency"
SERVICES = ["cloudformation"]


@tags(
    "axis:rejection", "cap:c1", "concern:negative-classes", "plane:control",
    "resource:account-singleton:cfn-generated-template",
)
def run(ctx) -> None:
    """More concurrent CreateGeneratedTemplate calls than the documented limit of 5 in progress are
    refused with ConcurrentResourcesLimitExceeded (HTTP 429, not LimitExceeded) while at least one
    succeeds, and a refused name answers GeneratedTemplateNotFound (HTTP 404) on describe."""
    cfn = ctx.client("cloudformation")

    bucket = _create_scratch_bucket(ctx)

    # A single CreateGeneratedTemplate scanning only one (nonexistent)
    # resource identifier completes its background scan so quickly that,
    # even fired concurrently, no more than a couple of requests are ever
    # simultaneously "InProgress"/"Pending" -- never actually approaching the
    # limit of 5, regardless of how many requests are fired at once. Give
    # each request many resource identifiers to scan (well under the
    # separate 500-resources-per-request cap) so each one's InProgress
    # window is long enough for concurrently-fired requests to genuinely
    # overlap and collide with the account-wide limit.
    RESOURCES_PER_CALL = 100
    NUM_CALLS = 10

    LIMIT_CODES = ("ConcurrentResourcesLimitExceededException", "ConcurrentResourcesLimitExceeded")

    def _create(index, name):
        resources = [
            {"ResourceType": "AWS::S3::Bucket", "ResourceIdentifier": {"BucketName": f"{bucket}-{index}-{j}"}}
            for j in range(RESOURCES_PER_CALL)
        ]
        # Firing many CreateGeneratedTemplate requests at once can trip CFN's
        # request-rate throttling (a distinct, transient concern from the
        # per-account in-progress-template limit this check is actually
        # probing) before the account-wide limit is even reached. Retry
        # ThrottlingException within a generous bound and with jittered
        # backoff (so threads desynchronize instead of re-colliding) before
        # giving up.
        deadline = time.monotonic() + 240
        while True:
            try:
                cfn.create_generated_template(GeneratedTemplateName=name, Resources=resources)
                return (name, None, None, None)
            except ClientError as e:
                code = e.response["Error"]["Code"]
                if code == "ThrottlingException" and time.monotonic() < deadline:
                    time.sleep(random.uniform(2.0, 6.0))
                    continue
                status = e.response["ResponseMetadata"]["HTTPStatusCode"]
                return (name, code, status, e.response["Error"].get("Message", ""))

    created = []
    ctx.on_cleanup(lambda: _cleanup_generated_templates(cfn, created))

    all_results = []
    limit_errors = []
    rejected_names = []
    other_errors = []
    # Escalate across a bounded number of rounds: if a round doesn't surface
    # the limit (e.g. this round's scans still resolved before enough of
    # them could overlap), pile on more outstanding in-progress templates
    # from a fresh round on top of whatever's already outstanding from
    # previous rounds, rather than assuming a single fixed batch size is
    # always enough to exceed the account's current in-progress count.
    for round_index in range(3):
        names = [ctx.unique_name(f"sim2real-behav-gt{round_index}-{i}-") for i in range(NUM_CALLS)]
        with ThreadPoolExecutor(max_workers=len(names)) as pool:
            results = list(pool.map(lambda item: _create(*item), enumerate(names)))
        all_results.extend(results)
        for name, code, status, message in results:
            if code is None:
                created.append(name)
            elif code in LIMIT_CODES:
                limit_errors.append((code, status, message))
                rejected_names.append(name)
            else:
                other_errors.append(code)
        if limit_errors or other_errors:
            break

    # Positive control: if nothing ever succeeded, the account/credentials may be broken
    # for this API entirely, which would make an all-rejected result indistinguishable
    # from "CreateGeneratedTemplate never works here".
    assert created, (
        f"expected at least one of {len(all_results)} concurrent CreateGeneratedTemplate "
        f"calls to succeed as a positive control, but none did (other_errors={other_errors})"
    )
    assert not other_errors, f"unexpected errors while probing the concurrency limit: {other_errors}"
    assert limit_errors, (
        f"expected at least one ConcurrentResourcesLimitExceededException among "
        f"{len(all_results)} concurrent CreateGeneratedTemplate calls, but all "
        f"{len(created)} succeeded"
    )
    # The message closes with a per-request Request ID, so its stable prefix and suffix are graded.
    for code, status, message in limit_errors:
        assert code == "ConcurrentResourcesLimitExceeded", (
            f"expected error code 'ConcurrentResourcesLimitExceeded', got {code!r}"
        )
        assert status == 429, f"expected HTTP 429 for {code}, got {status}"
        assert message.startswith(
            "Rate exceeded. Concurrent template generation limit exceeded. (Service: "
        ) and message.endswith("; Proxy: null)"), f"unexpected limit message {message!r}"

    # Independent read, through a different operation than the one that rejected it: a
    # name that hit the concurrency limit must never have actually come into existence.
    probe_name = rejected_names[0]
    try:
        cfn.describe_generated_template(GeneratedTemplateName=probe_name)
    except ClientError as e:
        code = e.response["Error"]["Code"]
        status = e.response["ResponseMetadata"]["HTTPStatusCode"]
        assert code == "GeneratedTemplateNotFound", (
            f"expected GeneratedTemplateNotFound for rejected template {probe_name!r}, got {code}"
        )
        assert status == 404, f"expected HTTP 404 for GeneratedTemplateNotFound, got {status}"
        # The message closes with a per-request Request ID, so its stable prefix and suffix are graded.
        message = e.response["Error"].get("Message", "")
        assert message.startswith(
            f"Template with arn {probe_name} does not exist (Service: "
        ) and message.endswith("; Proxy: null)"), f"unexpected not-found message {message!r}"
    else:
        raise AssertionError(
            f"expected describe_generated_template({probe_name!r}) to fail with "
            f"GeneratedTemplateNotFound after ConcurrentResourcesLimitExceeded, but it succeeded"
        )


def _create_scratch_bucket(ctx):
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-behav-gt-src-").lower().replace("_", "-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": "behavioral"}]})
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket))
    return bucket


def _cleanup_generated_templates(cfn, names):
    # A template whose scan is still running refuses deletion with a ValidationError
    # (operation in progress), so keep retrying until the scan settles; raise when the
    # bound runs out so a leaked template fails the teardown instead of passing silently.
    for name in names:
        deadline = time.monotonic() + 300
        while True:
            try:
                cfn.delete_generated_template(GeneratedTemplateName=name)
                break
            except ClientError as e:
                code = e.response["Error"]["Code"]
                if code == "GeneratedTemplateNotFound":
                    break
                busy = code in ("ValidationError", "ConcurrentResourcesLimitExceeded")
                if busy and time.monotonic() < deadline:
                    time.sleep(3)
                    continue
                raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
