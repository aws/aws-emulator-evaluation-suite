"""describe-registry-validation-rejected."""
from __future__ import annotations

import json

import urllib3
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest

from behavioral_harness import tags

CHECK = "describe-registry-validation-rejected"
GROUP = "error-semantics"
SERVICES = ["ecr"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """DescribeRegistry returns the account's registry id for an empty-object body, and rejects a
    top-level JSON array body with HTTP 400 SerializationException."""
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    status_ok, payload_ok = _raw_ecr_call(ctx, "DescribeRegistry", b"{}")
    assert status_ok == 200, f"expected 200 for well-formed request, got {status_ok}: {payload_ok}"
    assert payload_ok.get("registryId") == account_id, (
        f"expected registryId {account_id!r}, got {payload_ok.get('registryId')!r}: {payload_ok}"
    )

    status_bad, payload_bad = _raw_ecr_call(ctx, "DescribeRegistry", b"[]")
    assert status_bad == 400, f"expected 400 for malformed request, got {status_bad}: {payload_bad}"
    err_type = payload_bad.get("__type", "")
    code = err_type.split("#")[-1]
    assert code == "SerializationException", f"expected SerializationException, got {code!r}: {payload_bad}"


def _raw_ecr_call(ctx, target: str, body: bytes):
    client = ctx.client("ecr")
    endpoint = client.meta.endpoint_url
    signing_name = client.meta.service_model.signing_name
    creds = client._request_signer._credentials
    frozen = creds.get_frozen_credentials() if hasattr(creds, "get_frozen_credentials") else creds
    request = AWSRequest(
        method="POST",
        url=endpoint,
        data=body,
        headers={
            "Content-Type": "application/x-amz-json-1.1",
            "X-Amz-Target": f"AmazonEC2ContainerRegistry_V20150921.{target}",
        },
    )
    SigV4Auth(frozen, signing_name, ctx.region).add_auth(request)
    prepared = request.prepare()
    http = urllib3.PoolManager()
    resp = http.request(prepared.method, prepared.url, body=prepared.body, headers=dict(prepared.headers))
    data = resp.data
    payload = json.loads(data.decode("utf-8")) if data else {}
    return resp.status, payload


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
