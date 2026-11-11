"""50-bucket-fanout-object-isolation-and-negative-space."""
from __future__ import annotations

import hashlib
import os
import time
from concurrent.futures import ThreadPoolExecutor

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "50-bucket-fanout-object-isolation-and-negative-space"
GROUP = 'concurrency'
SERVICES = ['s3']

_N = 50
_KEY = 'payload.bin'
_DUPES = 8
_PAGE = 10
_LIST_DEADLINE_S = 120.0
_RESIDUAL_DEADLINE_S = 180.0

# Bounded retry so throttling on CreateBucket is a delay rather than a failure. The assertions
# need 50 buckets to exist simultaneously, not 50 simultaneous creations.
_CREATE_DEADLINE_S = 120.0


def _error_code(fn):
    """Call fn(); return the botocore Error.Code of the ClientError it raises. Success raises."""
    try:
        fn()
    except ClientError as exc:
        return exc.response.get('Error', {}).get('Code')
    raise AssertionError('the call succeeded; real AWS rejects it')


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:negative-classes",
      "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """Fifty concurrent buckets each hold one object under the same key with its own bytes, all list
    in a paginated ListBuckets walk, a sentinel is untouched, duplicates are refused, deletes stick.

    Reference: https://docs.aws.amazon.com/AmazonS3/latest/userguide/Welcome.html#ConsistencyModel
    """
    s3 = ctx.client('s3', config=Config(max_pool_connections=_N + 8,
                                        retries={'mode': 'standard', 'max_attempts': 3}))
    region = ctx.region
    runid = ctx.unique_name('')

    def _create_kw(bucket: str) -> dict:
        # us-east-1 is CreateBucket's default region and rejects an explicit
        # LocationConstraint for it; every other region requires one.
        kw = {'Bucket': bucket}
        if region != 'us-east-1':
            kw['CreateBucketConfiguration'] = {'LocationConstraint': region}
        return kw

    def _purge(bucket: str) -> None:
        keys = [{'Key': o['Key']}
                for page in s3.get_paginator('list_objects_v2').paginate(Bucket=bucket)
                for o in page.get('Contents', [])]
        if keys:
            s3.delete_objects(Bucket=bucket, Delete={'Objects': keys})
        s3.delete_bucket(Bucket=bucket)

    sentinel = f'sim2real-behav-d1-sentinel-{runid}'
    s3.create_bucket(**_create_kw(sentinel))
    ctx.on_cleanup(lambda: _purge(sentinel))
    s3.put_object(Bucket=sentinel, Key='sentinel', Body=b'SENTINEL')

    buckets = [f'sim2real-behav-d1-{runid}-{i:02d}' for i in range(_N)]
    bodies = {b: (f'bucket-{i:02d}-'.encode() + os.urandom(1000))
              for i, b in enumerate(buckets)}

    def _make(bucket: str) -> str | None:
        deadline = time.time() + _CREATE_DEADLINE_S
        attempt = 0
        while True:
            try:
                s3.create_bucket(**_create_kw(bucket))
                ctx.on_cleanup(lambda b=bucket: _purge(b))
                return None
            except ClientError as exc:
                code = exc.response.get('Error', {}).get('Code')
                if code not in ('OperationAborted', 'SlowDown', '503') or time.time() > deadline:
                    return f'{bucket}: {code}'
                attempt += 1
                time.sleep(min(2.0, 0.1 * attempt) + 0.05 * (attempt % 3))

    with ThreadPoolExecutor(max_workers=_N) as pool:
        failed = [e for e in pool.map(_make, buckets) if e is not None]
    assert failed == [], f'CreateBucket failed for {len(failed)} of {_N} buckets: {failed!r}'

    def _put(bucket: str) -> tuple[str, str]:
        r = s3.put_object(Bucket=bucket, Key=_KEY, Body=bodies[bucket])
        return bucket, r['ETag'].strip('"')

    with ThreadPoolExecutor(max_workers=_N) as pool:
        put_etags = dict(pool.map(_put, buckets))

    def _head(bucket: str) -> str | None:
        try:
            s3.head_bucket(Bucket=bucket)
            return None
        except ClientError as exc:
            return f'{bucket}: {exc.response.get("Error", {}).get("Code")}'

    with ThreadPoolExecutor(max_workers=_N) as pool:
        headless = [e for e in pool.map(_head, buckets) if e is not None]
    assert headless == [], f'HeadBucket failed after a successful CreateBucket: {headless!r}'

    # ListBuckets after CreateBucket is not documented as strongly consistent, so it is polled.
    def _walk() -> list[str]:
        names, token, pages = [], None, 0
        while True:
            kw = {'MaxBuckets': _PAGE}
            if token:
                kw['ContinuationToken'] = token
            resp = s3.list_buckets(**kw)
            page = [b['Name'] for b in resp.get('Buckets', [])]
            assert len(page) <= _PAGE, (
                f'ListBuckets returned {len(page)!r} buckets for MaxBuckets={_PAGE!r}'
            )
            names += page
            pages += 1
            token = resp.get('ContinuationToken')
            if not token:
                return names + [f'#pages={pages}']

    deadline = time.time() + _LIST_DEADLINE_S
    while True:
        walk = _walk()
        pages = int(walk.pop()[len('#pages='):])
        if set(buckets) <= set(walk):
            break
        assert time.time() < deadline, (
            f'ListBuckets never listed all {_N!r} buckets within {_LIST_DEADLINE_S!r}s; '
            f'{sorted(set(buckets) - set(walk))!r} were still missing'
        )
        time.sleep(2.0)

    assert len(walk) == len(set(walk)), (
        f'the paginated ListBuckets walk repeated a name -- the ContinuationToken is not a cursor: '
        f'{sorted({n for n in walk if walk.count(n) > 1})!r}'
    )
    assert pages >= 5, (
        f'MaxBuckets={_PAGE!r} over {len(walk)!r} buckets produced only {pages!r} page(s); '
        f'MaxBuckets was ignored, so the walk was never a paginated walk'
    )
    assert sentinel in walk, (
        f'the ListBuckets walk of {len(walk)!r} buckets omits the pre-existing sentinel '
        f'{sentinel!r} -- the listing is echoing this run rather than reading the registry'
    )

    # ETag == MD5(body) holds because every PUT here is single-part and unencrypted.
    def _read(bucket: str) -> tuple[str, bytes, str, list[str], int]:
        got = s3.get_object(Bucket=bucket, Key=_KEY)
        body = got['Body'].read()
        listing = s3.list_objects_v2(Bucket=bucket)
        return (bucket, body, got['ETag'].strip('"'),
                sorted(o['Key'] for o in listing.get('Contents', [])),
                listing['KeyCount'])

    with ThreadPoolExecutor(max_workers=_N) as pool:
        reads = list(pool.map(_read, buckets))

    read_map = {b: body for b, body, _, _, _ in reads}
    assert read_map == bodies, (
        'the object read back from each bucket is not the object written to it. '
        + repr({b: (bodies[b][:14], read_map[b][:14]) for b in buckets
                if read_map[b] != bodies[b]})
    )
    for bucket, body, etag, keys, key_count in reads:
        assert etag == hashlib.md5(body).hexdigest(), (
            f'{bucket}: GetObject reported ETag {etag!r} but MD5 of the {len(body)!r} bytes it '
            f'returned is {hashlib.md5(body).hexdigest()!r} -- the digest does not describe the '
            f'stored bytes'
        )
        assert etag == put_etags[bucket], (
            f'{bucket}: PutObject reported ETag {put_etags[bucket]!r} and GetObject {etag!r}'
        )
        assert keys == [_KEY], (
            f'{bucket}: ListObjectsV2 returned {keys!r}, expected exactly [{_KEY!r}] -- '
            f'{len(keys)!r} keys in a bucket written exactly one means the keyspace is shared'
        )
        assert key_count == 1, f'{bucket}: KeyCount was {key_count!r}, expected 1'

    sent_keys = sorted(o['Key'] for o in
                       s3.list_objects_v2(Bucket=sentinel).get('Contents', []))
    assert sent_keys == ['sentinel'], (
        f'the sentinel bucket holds {sent_keys!r} after the fan-out, expected ["sentinel"] only'
    )
    sent_body = s3.get_object(Bucket=sentinel, Key='sentinel')['Body'].read()
    assert sent_body == b'SENTINEL', f'the sentinel object body is now {sent_body[:32]!r}'

    # Buckets from a concurrent run of this check must not hold this run's bodies.
    ours = set(buckets) | {sentinel}
    siblings = [n for n in walk if n.startswith('sim2real-behav-d1-') and n not in ours]
    for other in siblings:
        try:
            leaked = s3.get_object(Bucket=other, Key=_KEY)['Body'].read()
        except ClientError:
            continue  # a sibling run's bucket we cannot read tells us nothing either way
        assert leaked not in set(bodies.values()), (
            f'a body written by THIS run turned up in {other!r}, a bucket belonging to a '
            f'different run'
        )

    dupes = buckets[:_DUPES]
    with ThreadPoolExecutor(max_workers=_DUPES) as pool:
        codes = list(pool.map(lambda b: _error_code(lambda: s3.create_bucket(**_create_kw(b))),
                              dupes))
    assert codes == ['BucketAlreadyOwnedByYou'] * _DUPES, (
        f'concurrent CreateBucket on names this account already owns returned {codes!r}, '
        f'expected BucketAlreadyOwnedByYou for all {_DUPES!r}'
    )
    for bucket in dupes:
        after = s3.get_object(Bucket=bucket, Key=_KEY)['Body'].read()
        assert after == bodies[bucket], (
            f'{bucket}: the rejected CreateBucket truncated or replaced the object -- body is now '
            f'{len(after)!r} bytes starting {after[:14]!r}'
        )
        keys = sorted(o['Key'] for o in s3.list_objects_v2(Bucket=bucket).get('Contents', []))
        assert keys == [_KEY], f'{bucket}: keys after the rejected CreateBucket are {keys!r}'

    # A deleted bucket can still answer HeadBucket briefly, so the residual check polls.
    def _rm(bucket: str) -> str | None:
        try:
            _purge(bucket)
            return None
        except ClientError as exc:
            return f'{bucket}: {exc.response.get("Error", {}).get("Code")}'

    with ThreadPoolExecutor(max_workers=_N) as pool:
        undeleted = [e for e in pool.map(_rm, buckets) if e is not None]
    assert undeleted == [], f'DeleteBucket failed for: {undeleted!r}'

    deadline = time.time() + _RESIDUAL_DEADLINE_S
    while True:
        with ThreadPoolExecutor(max_workers=_N) as pool:
            alive = [b for b, e in zip(buckets, pool.map(_head, buckets)) if e is None]
        if not alive:
            break
        assert time.time() < deadline, (
            f'{len(alive)!r} of {_N!r} buckets still answer HeadBucket {_RESIDUAL_DEADLINE_S!r}s '
            f'after a successful DeleteBucket: {sorted(alive)!r}'
        )
        time.sleep(3.0)

    final = _walk()
    final.pop()
    still = sorted(set(buckets) & set(final))
    assert still == [], f'ListBuckets still lists deleted buckets: {still!r}'
    assert sentinel in final, (
        f'the sentinel bucket vanished from ListBuckets while the fan-out was deleted -- '
        f'the delete reached beyond the {_N!r} named buckets'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
