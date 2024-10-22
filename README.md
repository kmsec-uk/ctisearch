# `ctisearch`

A collection of similar interfaces to Shodan, URLScan, and VirusTotal searches.

> [!WARNING]  
> This is under slow development in my spare time. You may experience bugs or
> breaking changes between versions.

This provides a consistent experience for searching:

* [Shodan search](https://shodan.io/)
* [URLScan search](https://urlscan.io/search/#)
* [VirusTotal intelligence search](https://virustotal.readme.io/reference/intelligence-search)

The motivation for this was to make automation of searches from all three feel
familiar and consistent, as well as provide asynchronous interfaces to Shodan
and URLScan at the same time. The official VirusTotal library is already
asynchronous, so under the hood, this package is a light wrapper around `vt-py`.

## Usage

... more details to come, but for now, check out the docstrings for examples and
the example below, which should explain some of the semantics.

## Example

```python
import asyncio
from ctisearch import ShodanSearch

async def count_cs_watermarks():
    """an example"""
    import os

    apikey = os.environ.get("SHODAN_API_KEY")

    async def watermark_extractor(instance, d: dict):
        """my custom processor to extract the cobalt strike watermark only"""
        try:
            return d["cobalt_strike_beacon"]["x64"]["watermark"]
        except KeyError:
            return None

    cobalt_strike = ShodanSearch(
        query='product:"Cobalt Strike Beacon"',
        apikey=apikey,
        fields=["cobalt_strike_beacon"],
        callback=watermark_extractor,
    )

    await cobalt_strike.search()

    # count watermarks
    counts = {}
    for watermark in cobalt_strike.processed:
        try:
            counts[watermark] += 1
        except KeyError:
            counts[watermark] = 1
    most_prevalent = max(counts, key=counts.get)
    print(
        f"The most popular Cobalt Strike Watermark is {most_prevalent} with {counts[most_prevalent]} on the internet"
    )


if __name__ == "__main__":
    asyncio.run(count_cs_watermarks())

```