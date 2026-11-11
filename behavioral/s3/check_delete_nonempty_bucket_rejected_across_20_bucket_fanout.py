"""delete-nonempty-bucket-rejected-across-20-bucket-fanout."""
from __future__ import annotations

import os
import time
from concurrent.futures import ThreadPoolExecutor

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-nonempty-bucket-rejected-across-20-bucket-fanout"
GROUP = 'concurrency'
SERVICES = ['s3']

_N = 20
_KEY = 'payload.bin'
_RESIDUAL_DEADLINE_S = 180.0
#: What _absent returns when its call succeeds; no S3 error code can equal it.
_SUCCEEDED = '<the call succeeded>'


def _error(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message) if a ClientError is raised.

    An unexpected SUCCESS raises rather than returning a falsy sentinel: an emulator that deletes a
    non-empty bucket is the defect this check exists to catch, and it must not read as a code
    mismatch.
    """
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get('Error', {})
        return err.get('Code'), err.get('Message')
    raise AssertionError('DeleteBucket succeeded on a non-empty bucket; real AWS rejects that')


def _absent(fn) -> str:
    """Call fn(); return _SUCCEEDED when it succeeds, else the botocore Error.Code.

    The inverse of ``_error`` and deliberately separate: a helper that raises on success cannot
    be reused where success is the expected outcome. _SUCCEEDED is a value no error code can equal.
    """
    try:
        fn()
    except ClientError as exc:
        return exc.response.get('Error', {}).get('Code') or 'ClientError-with-no-code'
    return _SUCCEEDED


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """Across twenty buckets that each hold one object under the same key, emptying bucket 0 makes only
    bucket 0 deletable: DeleteBucket on the other nineteen fails with BucketNotEmpty and its exact
    message and leaves each one holding its own byte-exact body."""
    s3 = ctx.client('s3', config=Config(max_pool_connections=_N + 8,
                                        retries={'mode': 'standard', 'max_attempts': 3}))
    region = ctx.region
    runid = ctx.unique_name('')

    def _create_kw(bucket: str) -> dict:
        kw = {'Bucket': bucket}
        # us-east-1 is the one region CreateBucket rejects a LocationConstraint for.
        if region != 'us-east-1':
            kw['CreateBucketConfiguration'] = {'LocationConstraint': region}
        return kw

    def _purge(bucket: str) -> None:
        # The emptied bucket is deleted by the check body itself; its teardown has nothing to do.
        try:
            keys = [{'Key': o['Key']}
                    for page in s3.get_paginator('list_objects_v2').paginate(Bucket=bucket)
                    for o in page.get('Contents', [])]
        except ClientError as exc:
            if exc.response.get('Error', {}).get('Code') == 'NoSuchBucket':
                return
            raise
        if keys:
            failed = s3.delete_objects(Bucket=bucket, Delete={'Objects': keys}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        try:
            s3.delete_bucket(Bucket=bucket)
        except ClientError as err:
            if err.response["Error"]["Code"] != "NoSuchBucket":
                raise

    buckets = [f'sim2real-behav-d1e-{runid}-{i:02d}' for i in range(_N)]
    bodies = {b: (f'bucket-{i:02d}-'.encode() + os.urandom(500))
              for i, b in enumerate(buckets)}

    def _make(bucket: str) -> str | None:
        try:
            s3.create_bucket(**_create_kw(bucket))
            ctx.on_cleanup(lambda b=bucket: _purge(b))
            s3.put_object(Bucket=bucket, Key=_KEY, Body=bodies[bucket])
            return None
        except ClientError as exc:
            return f'{bucket}: {exc.response.get("Error", {}).get("Code")}'

    with ThreadPoolExecutor(max_workers=_N) as pool:
        failed = [e for e in pool.map(_make, buckets) if e is not None]
    assert failed == [], f'setup fan-out failed for {len(failed)} of {_N}: {failed!r}'

    # every bucket really does hold exactly its own object -- the setup is real
    def _keys(bucket: str) -> tuple[str, list[str]]:
        return bucket, sorted(o['Key'] for o in
                              s3.list_objects_v2(Bucket=bucket).get('Contents', []))

    with ThreadPoolExecutor(max_workers=_N) as pool:
        before = dict(pool.map(_keys, buckets))
    assert before == {b: [_KEY] for b in buckets}, (
        'the fan-out did not put exactly one object in each bucket: '
        + repr({b: k for b, k in before.items() if k != [_KEY]})
    )

    # ---- break exactly one thing: empty bucket 0, leave the other nineteen populated ----
    victim, siblings = buckets[0], buckets[1:]
    s3.delete_object(Bucket=victim, Key=_KEY)
    emptied = s3.list_objects_v2(Bucket=victim)
    assert emptied['KeyCount'] == 0 and 'Contents' not in emptied, (
        f'{victim!r} still lists {emptied.get("Contents")!r} after DeleteObject'
    )

    # the delete did not reach into any sibling -- this is what makes the nineteen rejections mean
    # something rather than being a coincidence of a shared store
    with ThreadPoolExecutor(max_workers=_N) as pool:
        after_delete = dict(pool.map(_keys, siblings))
    assert after_delete == {b: [_KEY] for b in siblings}, (
        f'DeleteObject on {victim!r} emptied sibling buckets that share the key name: '
        + repr({b: k for b, k in after_delete.items() if k != [_KEY]})
    )

    # ---- the negative: nineteen concurrent DeleteBucket calls on non-empty buckets ----
    with ThreadPoolExecutor(max_workers=len(siblings)) as pool:
        codes = list(pool.map(
            lambda b: _error(lambda: s3.delete_bucket(Bucket=b)), siblings))
    assert codes == [('BucketNotEmpty', 'The bucket you tried to delete is not empty')] * len(siblings), (
        f'DeleteBucket on {len(siblings)!r} non-empty buckets returned {codes!r}, expected '
        f'BucketNotEmpty with AWS\'s exact message for every one'
    )

    # ---- effect ABSENT: all nineteen survive, with their own bytes ----
    def _read(bucket: str) -> tuple[str, bytes]:
        return bucket, s3.get_object(Bucket=bucket, Key=_KEY)['Body'].read()

    with ThreadPoolExecutor(max_workers=_N) as pool:
        surviving = dict(pool.map(_read, siblings))
    assert surviving == {b: bodies[b] for b in siblings}, (
        'a rejected DeleteBucket still destroyed or altered an object: '
        + repr({b: (bodies[b][:14], surviving.get(b, b'')[:14]) for b in siblings
                if surviving.get(b) != bodies[b]})
    )
    with ThreadPoolExecutor(max_workers=_N) as pool:
        gone = [f'{b}: {e}' for b, e in zip(siblings, pool.map(
            lambda b: _absent(lambda: s3.head_bucket(Bucket=b)), siblings)) if e != _SUCCEEDED]
    assert gone == [], f'a rejected DeleteBucket removed the bucket anyway: {gone!r}'

    # ---- positive control, same file: the bucket we DID empty deletes cleanly ----
    s3.delete_bucket(Bucket=victim)
    deadline = time.time() + _RESIDUAL_DEADLINE_S
    while True:
        try:
            s3.head_bucket(Bucket=victim)
        except ClientError as exc:
            code = exc.response.get('Error', {}).get('Code')
            assert code == '404', (
                f'HeadBucket on the deleted {victim!r} returned {code!r}, expected 404'
            )
            break
        assert time.time() < deadline, (
            f'{victim!r} still answers HeadBucket {_RESIDUAL_DEADLINE_S!r}s after a successful '
            f'DeleteBucket on an emptied bucket'
        )
        time.sleep(3.0)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
