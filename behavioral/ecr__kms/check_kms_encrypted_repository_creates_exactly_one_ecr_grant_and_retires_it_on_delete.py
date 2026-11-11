"""kms-encrypted-repository-creates-exactly-one-ecr-grant-and-retires-it-on-delete."""
from __future__ import annotations

import gzip
import hashlib
import io
import json
import tarfile
import time
import urllib.error
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags


def _routed_request(ctx, url, data=None, headers=None, **kwargs):
    """A urllib Request that reaches ``url`` on the target, with ``ctx.endpoint_route``'s headers."""
    target, route = ctx.endpoint_route(url)
    return urllib.request.Request(target, data=data, headers={**(headers or {}), **route}, **kwargs)


DOCKER_V2 = "application/vnd.docker.distribution.manifest.v2+json"
DOCKER_CONFIG = "application/vnd.docker.container.image.v1+json"
DOCKER_LAYER = "application/vnd.docker.image.rootfs.diff.tar.gzip"

GRANT_TIMEOUT_S = 60.0
RETIRE_TIMEOUT_S = 90.0
GENERATE_DATA_KEY_OPS = frozenset({"GenerateDataKey", "GenerateDataKeyWithoutPlaintext"})


def _client_error(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"real AWS refuses this call, but it SUCCEEDED and returned {result!r}")


_SUCCEEDED = object()


def _error_code(fn):
    """The error code fn() raised, or the _SUCCEEDED sentinel (which no error code can equal);
    for teardown probes only."""
    try:
        fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code")
    return _SUCCEEDED


def _poll_until(probe, predicate, *, timeout_s, interval_s, description):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not observed within {timeout_s}s; last saw {last!r}")


def _sha256_digest(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _gzip_tar(entries):
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w") as tar:
        for path, payload in entries:
            info = tarfile.TarInfo(name=path)
            info.size = len(payload)
            info.mtime = 0
            info.mode = 0o644
            tar.addfile(info, io.BytesIO(payload))
    uncompressed = raw.getvalue()
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb", mtime=0) as gz:
        gz.write(uncompressed)
    return buf.getvalue(), uncompressed


def _delete_repo_verified(ecr, name, timeout_s=45):
    code = _error_code(lambda: ecr.delete_repository(repositoryName=name, force=True))
    if code == "RepositoryNotFoundException":
        return
    if code is not _SUCCEEDED:
        print(f"LEAK: delete_repository({name}, force=True) failed with {code!r}")
        raise AssertionError(f"could not delete repository {name}: {code!r}")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if _error_code(
            lambda: ecr.describe_repositories(repositoryNames=[name])
        ) == "RepositoryNotFoundException":
            return
        time.sleep(1.0)
    print(f"LEAK: repository {name} still present {timeout_s}s after force delete")
    raise AssertionError(f"repository {name} still present {timeout_s}s after force delete")


def _retire_key(kms, key_id):
    """Disable the key, then schedule deletion at KMS's minimum 7-day pending window."""
    disable_code = _error_code(lambda: kms.disable_key(KeyId=key_id))
    code = _error_code(
        lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7)
    )
    settled = (_SUCCEEDED, "NotFoundException", "KMSInvalidStateException")
    if code not in settled:
        raise AssertionError(f"could not schedule deletion of KMS key {key_id}: {code!r}")
    if disable_code not in settled:
        raise RuntimeError(f"could not disable KMS key {key_id}: {disable_code!r}")


def _grant_identity(grant):
    """The authorization a grant encodes, without the per-call GrantId and CreationDate."""
    return (
        grant["GranteePrincipal"],
        grant.get("RetiringPrincipal"),
        grant["IssuingAccount"],
        tuple(sorted(grant["Operations"])),
        json.dumps(grant.get("Constraints", {}), sort_keys=True),
    )


def _grants(kms, key_id):
    """Every grant on the key, paginated, as {GrantId: grant}."""
    found = {}
    for page in kms.get_paginator("list_grants").paginate(KeyId=key_id):
        for grant in page["Grants"]:
            found[grant["GrantId"]] = grant
    return found


def _http_get(ctx, url):
    try:
        with urllib.request.urlopen(_routed_request(ctx, url), timeout=60) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read() if hasattr(exc, "read") else b""
    except urllib.error.URLError as exc:
        raise AssertionError(f"the presigned layer URL is unreachable: {exc}") from exc


def _upload_blob(ecr, repo, data):
    digest = _sha256_digest(data)
    upload_id = ecr.initiate_layer_upload(repositoryName=repo)["uploadId"]
    ecr.upload_layer_part(
        repositoryName=repo,
        uploadId=upload_id,
        partFirstByte=0,
        partLastByte=len(data) - 1,
        layerPartBlob=data,
    )
    done = ecr.complete_layer_upload(
        repositoryName=repo, uploadId=upload_id, layerDigests=[digest]
    )
    assert done["layerDigest"] == digest, (
        f"CompleteLayerUpload committed {done.get('layerDigest')!r} for bytes hashing to {digest!r}"
    )
    return digest, len(data)


CHECK = "kms-encrypted-repository-creates-exactly-one-ecr-grant-and-retires-it-on-delete"
GROUP = "server-side"
SERVICES = ["ecr", "kms"]


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "concern:representation", "dp:api", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A KMS-encrypted ECR repository puts two identical ECR grants (Decrypt, GenerateDataKey) on
    the CMK and reports its full ARN; layers round-trip, an AES256 twin adds no grant, a
    cross-Region key is refused, and deleting the repository retires the grants.

    Reference: https://docs.aws.amazon.com/AmazonECR/latest/userguide/encryption-at-rest.html
    """
    ecr = ctx.client("ecr")
    kms = ctx.client("kms")

    key = kms.create_key(
        Description="sim2real: prove ECR uses a KMS grant for an encrypted repository",
        KeyUsage="ENCRYPT_DECRYPT",
        KeySpec="SYMMETRIC_DEFAULT",
        Tags=[
            {"TagKey": "sim2real", "TagValue": "ecr-kms-grant"},
            {"TagKey": "sim2real-managed", "TagValue": "true"},
        ],
    )["KeyMetadata"]
    key_id, key_arn = key["KeyId"], key["Arn"]
    ctx.on_cleanup(lambda: _retire_key(kms, key_id))
    assert key["Enabled"] is True, (
        f"the freshly created CMK {key_id!r} is not Enabled ({key!r}); ECR could not use it and the "
        f"rest of this check would be measuring a disabled key"
    )
    described_arn = kms.describe_key(KeyId=key_id)["KeyMetadata"]["Arn"]
    assert described_arn == key_arn, (
        f"kms:DescribeKey reports ARN {described_arn!r} for the key CreateKey returned as "
        f"{key_arn!r}"
    )

    baseline_grants = _grants(kms, key_id)
    assert baseline_grants == {}, (
        f"a freshly created CMK already carries grants {sorted(baseline_grants)}; with a non-empty "
        f"baseline the grant-count assertion below is not evidence"
    )

    kms_repo = ctx.unique_name("sim2real-xsvc-ecr-kms-")
    created = ecr.create_repository(
        repositoryName=kms_repo,
        encryptionConfiguration={"encryptionType": "KMS", "kmsKey": key_arn},
        tags=[{"Key": "sim2real", "Value": "ecr-kms-grant"}],
    )["repository"]
    ctx.on_cleanup(lambda: _delete_repo_verified(ecr, kms_repo))
    assert created["encryptionConfiguration"]["encryptionType"] == "KMS", (
        f"CreateRepository echoed encryptionConfiguration "
        f"{created.get('encryptionConfiguration')!r}, expected encryptionType 'KMS'"
    )

    described_repo = ecr.describe_repositories(repositoryNames=[kms_repo])["repositories"][0]
    assert described_repo["encryptionConfiguration"]["kmsKey"] == key_arn, (
        f"DescribeRepositories reports kmsKey "
        f"{described_repo['encryptionConfiguration'].get('kmsKey')!r}; kms:DescribeKey reports the "
        f"key as {key_arn!r}. The two services must name the same key"
    )

    # ECR issues one authorization as two grants that differ only in GrantId and CreationDate.
    # KMS grant listing is eventually consistent, hence the poll.
    grants = _poll_until(
        lambda: _grants(kms, key_id),
        lambda found: len(found) >= 1,
        timeout_s=GRANT_TIMEOUT_S,
        interval_s=3.0,
        description=(
            f"kms:ListGrants showing the grant(s) ECR must create on {key_arn} for repository "
            f"{kms_repo!r} (KMS grant listing is eventually consistent)"
        ),
    )
    assert len(grants) == 2, (
        f"the key carries {len(grants)} grants after ONE KMS-encrypted repository was created: "
        f"{json.dumps(list(grants.values()), default=str)}. Real AWS creates exactly two identical "
        f"grants (confirmed on two independent replays); a different count means ECR is either "
        f"under- or over-granting on a customer key"
    )
    identities = {_grant_identity(g) for g in grants.values()}
    assert len(identities) == 1, (
        f"the two grants on {key_arn} do not collapse to one authorization once GrantId/CreationDate "
        f"are stripped out: {sorted(identities)!r}; ECR issuing the SAME authorization twice is the "
        f"measured behaviour, ECR issuing two DIFFERENT authorizations for one repository is real "
        f"over-granting"
    )
    grant = next(iter(grants.values()))
    assert "ecr" in grant["GranteePrincipal"].lower(), (
        f"the grant's GranteePrincipal is {grant.get('GranteePrincipal')!r}, which does not name ECR; "
        f"a grant to some other principal is not the grant that lets ECR encrypt this repository"
    )
    operations = set(grant["Operations"])
    assert "Decrypt" in operations, (
        f"the grant's Operations are {sorted(operations)} and do not include 'Decrypt'; ECR could "
        f"not serve a pull from this repository"
    )
    assert operations & GENERATE_DATA_KEY_OPS, (
        f"the grant's Operations are {sorted(operations)} and include none of "
        f"{sorted(GENERATE_DATA_KEY_OPS)}; ECR could not encrypt a newly pushed layer"
    )
    assert grant["KeyId"] == key_arn, (
        f"the grant names key {grant.get('KeyId')!r}, expected {key_arn!r}"
    )

    layer_gz, layer_raw = _gzip_tar([("sim2real/kms.txt", b"ecr-kms-encrypted-layer\n")])
    layer_digest, layer_size = _upload_blob(ecr, kms_repo, layer_gz)
    config = json.dumps(
        {
            "architecture": "amd64",
            "os": "linux",
            "config": {},
            "history": [],
            "rootfs": {"type": "layers", "diff_ids": [_sha256_digest(layer_raw)]},
        },
        sort_keys=True,
    ).encode()
    config_digest, config_size = _upload_blob(ecr, kms_repo, config)
    manifest = json.dumps(
        {
            "schemaVersion": 2,
            "mediaType": DOCKER_V2,
            "config": {"mediaType": DOCKER_CONFIG, "size": config_size, "digest": config_digest},
            "layers": [{"mediaType": DOCKER_LAYER, "size": layer_size, "digest": layer_digest}],
        },
        sort_keys=True,
    )
    put = ecr.put_image(
        repositoryName=kms_repo,
        imageManifest=manifest,
        imageManifestMediaType=DOCKER_V2,
        imageTag="kms",
    )
    assert put["image"]["imageId"]["imageDigest"] == _sha256_digest(manifest.encode()), (
        f"PutImage into a KMS-encrypted repository minted "
        f"{put['image']['imageId']['imageDigest']!r} for manifest bytes hashing to "
        f"{_sha256_digest(manifest.encode())!r}; encryption must not change the content address"
    )
    url = ecr.get_download_url_for_layer(
        repositoryName=kms_repo, layerDigest=layer_digest
    )["downloadUrl"]
    status, blob = _http_get(ctx, url)
    assert status == 200, f"the presigned layer URL returned HTTP {status!r}: {blob[:200]!r}"
    assert _sha256_digest(blob) == layer_digest, (
        f"the layer pulled from a KMS-encrypted repository hashes to {_sha256_digest(blob)!r}, "
        f"expected {layer_digest!r}; the decrypt path does not return the bytes that were pushed"
    )
    assert gzip.decompress(blob) == layer_raw, (
        "the layer pulled from the KMS-encrypted repository does not gunzip to the uploaded tar"
    )

    aes_repo = ctx.unique_name("sim2real-xsvc-ecr-aes-")
    aes_created = ecr.create_repository(
        repositoryName=aes_repo,
        encryptionConfiguration={"encryptionType": "AES256"},
        tags=[{"Key": "sim2real", "Value": "ecr-kms-grant-control"}],
    )["repository"]
    ctx.on_cleanup(lambda: _delete_repo_verified(ecr, aes_repo))
    assert aes_created["encryptionConfiguration"]["encryptionType"] == "AES256", (
        f"the control repository reports encryptionType "
        f"{aes_created['encryptionConfiguration'].get('encryptionType')!r}, expected 'AES256'"
    )
    assert aes_created["encryptionConfiguration"].get("kmsKey", "") == "", (
        f"an AES256 repository reports kmsKey "
        f"{aes_created['encryptionConfiguration'].get('kmsKey')!r}; AWS-owned encryption must name "
        f"no customer key"
    )
    control_grants = _grants(kms, key_id)
    assert set(control_grants) == set(grants), (
        f"the CMK's grants changed to {sorted(control_grants)} after an AES256 repository was "
        f"created (was {sorted(grants)}); a target that grants on every repository creation would "
        f"otherwise pass the grant-count leg for the wrong reason"
    )

    other_region = "us-east-1" if ctx.region != "us-east-1" else "us-west-2"
    foreign_key = ctx.client("kms", region=other_region).create_key(
        Description="sim2real: cross-Region CMK that must NOT be usable by ECR in another Region",
        Tags=[{"TagKey": "sim2real", "TagValue": "ecr-kms-grant-foreign"}],
    )["KeyMetadata"]
    ctx.on_cleanup(
        lambda: _retire_key(ctx.client("kms", region=other_region), foreign_key["KeyId"])
    )
    assert foreign_key["Arn"].split(":")[3] == other_region, (
        f"the foreign key ARN {foreign_key['Arn']!r} does not name Region {other_region!r}, so the "
        f"rejection below would not be about a cross-Region key"
    )
    foreign_repo = ctx.unique_name("sim2real-xsvc-ecr-foreign-")
    foreign_error = _client_error(
        lambda: ecr.create_repository(
            repositoryName=foreign_repo,
            encryptionConfiguration={"encryptionType": "KMS", "kmsKey": foreign_key["Arn"]},
            tags=[{"Key": "sim2real", "Value": "ecr-kms-grant-foreign"}],
        )
    )
    assert foreign_error.get("Code") == "KmsException", (
        f"CreateRepository answered {foreign_error!r} for a CMK in {other_region!r} while the caller "
        f"is in {ctx.region!r}; expected KmsException. Positive control: the same call with an "
        f"in-Region key succeeded above"
    )
    # The KMS request id inside the message is per request and exposed nowhere else.
    kms_refusal = (f"The Amazon ECR action failed due to a KMS exception: Invalid arn {other_region} "
                   f"(Service: AWSKMS; Status Code: 400; Error Code: NotFoundException; Request ID: ")
    foreign_message = foreign_error.get("Message", "")
    assert foreign_message.startswith(kms_refusal) and foreign_message.endswith("; Proxy: null)"), (
        f"CreateRepository with the {other_region!r} key was refused with {foreign_message!r}"
    )
    absent = _client_error(lambda: ecr.describe_repositories(repositoryNames=[foreign_repo]))
    assert absent.get("Code") == "RepositoryNotFoundException", (
        f"DescribeRepositories answered {absent!r} for {foreign_repo!r} after the refused create; "
        f"expected RepositoryNotFoundException"
    )
    assert absent.get("Message") == (
        f"The repository with name '{foreign_repo}' does not exist in the registry with id "
        f"'{created['registryId']}'"
    ), f"DescribeRepositories for {foreign_repo!r} was refused with {absent!r}"

    _delete_repo_verified(ecr, kms_repo)
    remaining = _poll_until(
        lambda: _grants(kms, key_id),
        lambda found: found == {},
        timeout_s=RETIRE_TIMEOUT_S,
        interval_s=5.0,
        description=(
            f"kms:ListGrants converging to empty on {key_arn} after repository {kms_repo!r} was "
            f"deleted (the grant ECR created must be retired, or a deleted repository leaves a live "
            f"grant on a customer key)"
        ),
    )
    assert remaining == {}, (
        f"the CMK still carries grants {sorted(remaining)} after the only repository using it was "
        f"deleted"
    )
    # ECR retires its grants; it does not disable or delete the key.
    still_enabled = kms.describe_key(KeyId=key_id)["KeyMetadata"]
    assert still_enabled["Enabled"] is True, (
        f"the customer's CMK is no longer Enabled after the repository using it was deleted: "
        f"{still_enabled!r}"
    )
    assert still_enabled["KeyState"] == "Enabled", (
        f"the CMK's KeyState is {still_enabled.get('KeyState')!r} after the repository delete, "
        f"expected 'Enabled'"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
