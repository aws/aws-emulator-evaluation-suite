"""list-type-registrations-pagination-stable-under-concurrent-registration."""
from __future__ import annotations

import io
import threading
import time
import uuid
import zipfile
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "list-type-registrations-pagination-stable-under-concurrent-registration"
GROUP = "ordering"
SERVICES = ["cloudformation"]

SEED_COUNT = 5


@tags("axis:happy-path", "cap:c2", "concern:representation", "plane:control")
def run(ctx) -> None:
    """IN_PROGRESS ListTypeRegistrations pages (MaxResults=2) stay exact under a concurrent call.

    While another RegisterType runs, no token repeats across pages, no seed registration still
    IN_PROGRESS afterwards is dropped, and the concurrently registered token appears at most once.
    """
    cfn = ctx.client("cloudformation")
    s3 = ctx.client("s3")

    bucket = ctx.unique_name("sim2real-cfn-reg-").lower().replace("_", "-")
    _create_bucket(ctx, s3, bucket)
    package_url = _put_dummy_package(s3, bucket)

    type_name = f"Sim2Real::Paging{uuid.uuid4().hex[:10]}::Widget"

    seed_tokens: set[str] = set()
    for _ in range(SEED_COUNT):
        token = cfn.register_type(
            Type="RESOURCE",
            TypeName=type_name,
            SchemaHandlerPackage=package_url,
            ClientRequestToken=str(uuid.uuid4()),
        )["RegistrationToken"]
        seed_tokens.add(token)
    assert len(seed_tokens) == SEED_COUNT, "each seed RegisterType call must be a distinct registration"

    concurrent_token_holder: list[str] = []
    start = threading.Event()

    def register_more() -> None:
        start.wait()
        token = cfn.register_type(
            Type="RESOURCE",
            TypeName=type_name,
            SchemaHandlerPackage=package_url,
            ClientRequestToken=str(uuid.uuid4()),
        )["RegistrationToken"]
        concurrent_token_holder.append(token)

    def paginate_all() -> list[str]:
        start.wait()
        seen: list[str] = []
        next_token = None
        page_num = 0
        while True:
            kwargs: dict = {
                "TypeName": type_name,
                "Type": "RESOURCE",
                "RegistrationStatusFilter": "IN_PROGRESS",
                "MaxResults": 2,
            }
            if next_token:
                kwargs["NextToken"] = next_token
            page = cfn.list_type_registrations(**kwargs)
            tokens = page.get("RegistrationTokenList", [])
            page_num += 1
            # A registration that has already raced out of IN_PROGRESS by the time this
            # page is fetched legitimately shrinks the candidate set below MaxResults, so
            # this bounds the protocol (never more than requested) without assuming the
            # seeded set survives long enough to force a second page.
            assert len(tokens) <= 2, (
                f"ListTypeRegistrations returned {len(tokens)} tokens for MaxResults=2 on page {page_num}"
            )
            seen.extend(tokens)
            next_token = page.get("NextToken")
            if not next_token:
                return seen
            # Widen the race window against the concurrent RegisterType call.
            time.sleep(0.3)

    with ThreadPoolExecutor(max_workers=2) as pool:
        reg_future = pool.submit(register_more)
        page_future = pool.submit(paginate_all)
        start.set()
        reg_future.result(timeout=30)
        collected = page_future.result(timeout=60)

    # Invariant 1: no page repeats a token already returned by an earlier page.
    assert len(collected) == len(set(collected)), (
        f"ListTypeRegistrations returned a duplicate token across pages: {collected}"
    )

    # Invariant 2: every registration that existed before pagination started, and
    # that is STILL IN_PROGRESS (the filter this traversal used), is present exactly
    # once -- a registration racing in mid-pagination must not cause an
    # already-seeded, still-IN_PROGRESS page to be skipped or dropped. A seed token
    # that has itself raced to COMPLETE/FAILED during the traversal window is
    # legitimately absent from an IN_PROGRESS-filtered listing -- that is correct
    # status-filter behavior, not a pagination defect, so it is excluded below.
    collected_set = set(collected)
    missing = seed_tokens - collected_set
    still_in_progress_missing = {
        tok for tok in missing if _registration_status(cfn, tok) == "IN_PROGRESS"
    }
    assert not still_in_progress_missing, (
        f"pagination dropped pre-existing IN_PROGRESS registrations: {still_in_progress_missing}"
    )


    # Invariant 3: the token created concurrently with pagination is a genuine
    # boundary case (SQS/pagination semantics guarantee neither its presence nor its
    # absence) -- but if it does show up, it must show up exactly once, never twice.
    concurrent_token = concurrent_token_holder[0]
    concurrent_count = collected.count(concurrent_token)
    assert concurrent_count <= 1, (
        f"registration created concurrently with pagination appeared {concurrent_count} times, expected 0 or 1"
    )


def _create_bucket(ctx, s3, bucket: str) -> None:
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "simparity-check", "Value": CHECK}]})

    def _cleanup() -> None:
        for obj in s3.list_objects_v2(Bucket=bucket).get("Contents", []):
            s3.delete_object(Bucket=bucket, Key=obj["Key"])
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup)


def _registration_status(cfn, token: str) -> str:
    resp = cfn.describe_type_registration(RegistrationToken=token)
    return resp["ProgressStatus"]


def _put_dummy_package(s3, bucket: str) -> str:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("README.txt", "sim2real placeholder schema handler package\n")
    s3.put_object(Bucket=bucket, Key="package.zip", Body=buf.getvalue())
    return f"s3://{bucket}/package.zip"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
