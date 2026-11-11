"""s3pointer-oversized-inline-payload-is-rejected-and-never-enqueued-while-the-pointer-form-is-accepted."""

from __future__ import annotations

import hashlib
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = (
    "s3pointer-oversized-inline-payload-is-rejected-and-never-enqueued-while-the-pointer-form-is-accepted"
)
GROUP = "data-plane"
SERVICES = ["ec2", "s3", "sqs", "ssm"]

#: The classic pointer-pattern threshold, and still the value an S3-pointer design is sized
#: against. It is not the SQS DEFAULT (see below) -- it is what a queue must be
#: configured down to in order to see it, which is why this check sets it rather than assuming it.
_CAPPED_LIMIT = 262144
#: On real AWS a queue created with no `MaximumMessageSize` reports 1048576, and accepts a body of exactly that many bytes.
_DEFAULT_LIMIT = 1048576
#: Larger than BOTH limits, and small enough that the refusal is the service's
#: `InvalidParameterValue` rather than the HTTP layer's 413 (measured: a 2 MiB body is refused with
#: `{"Code": "413", "Message": "HTTP content length exceeded 2097152 bytes."}`, which is not a
#: service error code and is therefore not assertable as one).
_PAYLOAD_BYTES = 1572864
_KEY = "payloads/reduce-input.bin"


@tags(
    "axis:rejection",
    "concern:data-plane",
    "concern:e2e",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
    "cap:c1",
)
def run(ctx) -> None:
    """A payload larger than the queue's MaximumMessageSize is refused InvalidParameterValue and never
    enqueued, on a 256 KiB queue and a default one alike, while its S3-pointer form is accepted, received
    and resolved to the payload's bytes."""
    s3 = ctx.client("s3")
    sqs = ctx.client("sqs")
    name = ctx.unique_name("sim2real-s3ptr-bnd-")
    bucket = name + "-bkt"
    payload = _payload_bytes(name, _PAYLOAD_BYTES)

    s3.create_bucket(
        Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
    )
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": _tags_for(name)})

    capped = sqs.create_queue(
        QueueName=name + "-capped",
        Attributes={"MaximumMessageSize": str(_CAPPED_LIMIT)},
        tags={"sim2real": "s3pointer-boundary"},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=capped))
    default = sqs.create_queue(
        QueueName=name + "-default", tags={"sim2real": "s3pointer-boundary"}
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=default))

    capped_limit = int(_attr(sqs, capped, "MaximumMessageSize"))
    default_limit = int(_attr(sqs, default, "MaximumMessageSize"))
    assert capped_limit == _CAPPED_LIMIT, (
        f"the queue this check capped at {_CAPPED_LIMIT} reports MaximumMessageSize "
        f"{capped_limit!r}"
    )
    assert default_limit == _DEFAULT_LIMIT, (
        f"a queue created with no MaximumMessageSize must report the service default "
        f"{_DEFAULT_LIMIT}; this one reports {default_limit!r}"
    )

    # --- the boundary, on each queue, driven by the limit the queue itself reported -------------
    accepted_md5 = {}
    for url, limit, label in ((capped, capped_limit, "capped"), (default, default_limit, "default")):
        at_limit = _payload_bytes(name + ":" + label, limit)
        assert len(at_limit) == limit, f"{label}: generated {len(at_limit)} bytes, wanted {limit}"
        sent = sqs.send_message(QueueUrl=url, MessageBody=at_limit.decode("ascii"))
        want_md5 = hashlib.md5(at_limit).hexdigest()
        assert sent["MD5OfMessageBody"] == want_md5, (
            f"{label}: a body of exactly {limit} bytes must be accepted intact; SQS hashed "
            f"{sent['MD5OfMessageBody']!r}, the bytes this check sent hash to {want_md5!r}"
        )
        accepted_md5[url] = want_md5

        too_long = (f"One or more parameters are invalid. Reason: Message must be shorter than "
                    f"{limit} bytes.")
        over = _payload_bytes(name + ":" + label + ":over", limit + 1)
        code = _error(
            lambda u=url, b=over: sqs.send_message(QueueUrl=u, MessageBody=b.decode("ascii"))
        )
        assert code == ("InvalidParameterValue", too_long), (
            f"{label}: a body of {limit + 1} bytes is one byte over the limit the queue reported "
            f"and must be refused with InvalidParameterValue {too_long!r}; SQS returned {code!r}"
        )

        big = _error(
            lambda u=url: sqs.send_message(QueueUrl=u, MessageBody=payload.decode("ascii"))
        )
        assert big == ("InvalidParameterValue", too_long), (
            f"{label}: the {_PAYLOAD_BYTES}-byte job payload cannot travel inline and must be "
            f"refused with InvalidParameterValue {too_long!r}; SQS returned {big!r}"
        )

    # --- effect absent: only the at-limit body is in each queue ---------------------------------
    for url, label in ((capped, "capped"), (default, "default")):
        got = _receive_all(sqs, url, want=1, timeout_s=60)
        md5s = sorted({hashlib.md5(b.encode("ascii")).hexdigest() for b in got})
        assert md5s == [accepted_md5[url]], (
            f"{label}: exactly the one accepted at-limit body may be in the queue -- the two "
            f"refused bodies must never have been enqueued; the queue delivered bodies hashing to "
            f"{md5s!r}"
        )
        left = _hold_empty(sqs, url, seconds=20)
        assert left == [], (
            f"{label}: a refused body arrived late -- the queue delivered {[len(b) for b in left]!r} "
            f"bytes of body after the drain"
        )
        depth = _attr(sqs, url, "ApproximateNumberOfMessages")
        assert depth == "0", (
            f"{label}: a second, independent observable disagrees with the empty receive: "
            f"ApproximateNumberOfMessages={depth!r}"
        )

    # --- the pointer form of the SAME payload, on the 256 KiB-capped queue ----------------------
    s3.put_object(Bucket=bucket, Key=_KEY, Body=payload)
    pointer = json.dumps(
        {
            "job_id": name,
            "bucket": bucket,
            "key": _KEY,
            "op": "sha256",
            "bytes": len(payload),
        },
        sort_keys=True,
    )
    assert len(pointer.encode()) < 1024, (
        f"the pointer body is the whole point of the pattern and must be tiny; it is "
        f"{len(pointer.encode())} bytes"
    )
    sqs.send_message(QueueUrl=capped, MessageBody=pointer)
    delivered = _receive_all(sqs, capped, want=1, timeout_s=60)
    assert len(delivered) == 1, f"the pointer message did not arrive alone: {delivered!r}"
    body = json.loads(delivered[0])
    assert body["bucket"] == bucket and body["key"] == _KEY, (
        f"the delivered pointer names {body!r}, the check enqueued bucket {bucket!r} key {_KEY!r}"
    )
    assert body["bytes"] == len(payload), (
        f"the delivered pointer declares {body['bytes']!r} bytes, the payload is {len(payload)}"
    )
    obj = s3.get_object(Bucket=bucket, Key=body["key"])
    fetched = obj["Body"].read()
    assert obj["ContentLength"] == len(payload), (
        f"resolving the pointer returned {obj['ContentLength']!r} bytes, the payload is "
        f"{len(payload)}"
    )
    assert hashlib.sha256(fetched).hexdigest() == hashlib.sha256(payload).hexdigest(), (
        f"the bytes behind the pointer are not the payload: sha256 "
        f"{hashlib.sha256(fetched).hexdigest()!r} vs {hashlib.sha256(payload).hexdigest()!r}"
    )
    listed = _list_keys(s3, bucket, prefix="payloads/")
    assert listed == [_KEY], (
        f"the bucket holds {listed!r} under payloads/, the check wrote only {_KEY!r}"
    )


# ===== helpers =====
def _tags_for(name):
    return [
        {"Key": "Name", "Value": name},
        {"Key": "sim2real", "Value": "s3pointer-boundary"},
        {"Key": "sim2real:managed", "Value": "true"},
    ]


def _payload_bytes(nonce, n):
    """`n` deterministic ASCII bytes derived from `nonce`. ASCII because an SQS body is a string:
    the limit is in bytes, so a multi-byte character would make `len(body) != bytes on the wire`."""
    buf = b""
    i = 0
    while len(buf) < n:
        buf += hashlib.sha256((nonce + ":" + str(i)).encode()).hexdigest().encode("ascii")
        i += 1
    return buf[:n]


def _error(fn):
    """The (code, message) of the ClientError raised by fn. An unexpected SUCCESS raises, so it
    can never be confused with a code mismatch."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError("the call was expected to be refused but it succeeded")


def _attr(sqs, url, attribute):
    return sqs.get_queue_attributes(QueueUrl=url, AttributeNames=[attribute])["Attributes"][
        attribute
    ]


def _receive_all(sqs, url, want, timeout_s):
    """Receive and DELETE at least `want` bodies, returning them. Long-polls: SQS delivery is
    eventually consistent, so an immediate receive can legitimately come back empty."""
    out = []
    deadline = time.monotonic() + timeout_s
    while len(out) < want:
        resp = sqs.receive_message(
            QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=5, VisibilityTimeout=60
        )
        for m in resp.get("Messages", []):
            out.append(m["Body"])
            sqs.delete_message(QueueUrl=url, ReceiptHandle=m["ReceiptHandle"])
        if len(out) >= want:
            return out
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"only {len(out)} of {want} messages arrived on {url!r} within {timeout_s}s"
            )
    return out


def _hold_empty(sqs, url, seconds):
    """Keep receiving for `seconds`; return everything that arrived (ideally nothing)."""
    out = []
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        resp = sqs.receive_message(
            QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=5, VisibilityTimeout=60
        )
        for m in resp.get("Messages", []):
            out.append(m["Body"])
            sqs.delete_message(QueueUrl=url, ReceiptHandle=m["ReceiptHandle"])
    return out


def _list_keys(s3, bucket, prefix=""):
    keys = []
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket, Prefix=prefix):
        keys += [o["Key"] for o in page.get("Contents", [])]
    return sorted(keys)


def _empty_and_delete_bucket(s3, bucket):
    for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
        victims = [
            {"Key": o["Key"], "VersionId": o["VersionId"]}
            for o in page.get("Versions", []) + page.get("DeleteMarkers", [])
        ]
        if victims:
            failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": victims}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    s3.delete_bucket(Bucket=bucket)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
