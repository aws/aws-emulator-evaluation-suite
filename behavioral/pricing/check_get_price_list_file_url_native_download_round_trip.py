"""get-price-list-file-url-native-download-round-trip."""
from __future__ import annotations

import json
import ssl
import urllib.request
from datetime import datetime, timezone

from botocore.config import Config

from behavioral_harness import tags

CHECK = "get-price-list-file-url-native-download-round-trip"
GROUP = "e2e-data-plane-native"
SERVICES = ["pricing"]


def _pricing_client(ctx):
    """The Price List Query API is only served from us-east-1, eu-central-1 and ap-south-1, so the
    client pins us-east-1; ctx.client() honours the region override on every target."""
    return ctx.client(
        "pricing", region="us-east-1", config=Config(retries={"max_attempts": 8, "mode": "standard"})
    )


@tags("axis:happy-path", "cap:c5", "concern:data-plane", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """The URL GetPriceListFileUrl returns is fetchable over HTTPS and holds a parseable price list
    document for the requested service."""
    pricing = _pricing_client(ctx)
    now = datetime.now(timezone.utc)
    listing = pricing.list_price_lists(
        ServiceCode="AmazonSNS",
        EffectiveDate=now,
        CurrencyCode="USD",
        RegionCode="us-east-1",
        MaxResults=1,
    )
    price_lists = listing["PriceLists"]
    if not price_lists:
        raise AssertionError("no AmazonSNS us-east-1 USD price list is available to download")
    entry = price_lists[0]
    file_format = entry["FileFormats"][0]
    url_resp = pricing.get_price_list_file_url(PriceListArn=entry["PriceListArn"], FileFormat=file_format)
    url = url_resp["Url"]
    assert not (p := ctx.published_url_mismatch(url)), p

    target_url, route_headers = ctx.endpoint_route(url)
    request = urllib.request.Request(target_url, headers=route_headers)
    with urllib.request.urlopen(request, timeout=60, context=_ssl_context(ctx.http_verify)) as response:
        raw = response.read()

    if file_format.lower() == "json":
        document = json.loads(raw)
        assert document.get("offerCode") == "AmazonSNS", document.get("offerCode")
        assert document.get("products"), "expected a non-empty product catalog"
    else:
        assert raw.strip(), "downloaded price list file was empty"


def _ssl_context(verify) -> ssl.SSLContext:
    """An SSLContext honouring ``ctx.http_verify``: True, False, or a CA bundle path."""
    if verify is False:
        return ssl._create_unverified_context()
    return ssl.create_default_context(cafile=verify if isinstance(verify, str) else None)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
