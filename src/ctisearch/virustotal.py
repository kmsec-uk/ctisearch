#! /usr/bin/env python3.11
import asyncio
import json
from datetime import datetime, timezone
from typing import Any, Callable, Coroutine, Literal, Optional

import vt
from .base import BaseSearch, SearchException

vt_base = "/intelligence/search"


class VtException(SearchException):
    """Encapsulates all errors retrieving data from VirusTotal"""

    def __init__(self, message):
        self.message = message
        super().__init__(self.message)


class VtSearch(BaseSearch):
    """
    A class representing a VirusTotal Intelligence search. 
    This is a wrapper around the `vt-py` library, but provides some extra flexibility and cross-query compatibility.
    
    Note that for cross-query compatibility, you need to refactor existing VT Intelligence queries in the following ways:

    * Remove the `entity:` prefix and provide it as a parameter
    * Remove any date modifiers like `fs:` from the query and instead use the class parameter.
    
    Example:
    
    ```python
    async def test():
        import os

        apikey = os.environ.get("VT_API_KEY")
        
        s = VtSearch(
            entity="domain",
            query="domain:*googl*",
            since_date=1629000360000,
            apikey=apikey,
            limit=200,
        )

        await s.search()

        print("processed:", len(s.processed), "resolved:", str(s.resolved))

    if __name__ == "__main__":
        asyncio.run(test())
    ```
    Attributes
    ----------
    processed : list
        The results after you have processed all results. If a callback function is not specified, this will contain `dict`s of vt search results along with metadata about the search in d["meta"]
    resolved : int
        The number of results from the search triaged by the internal `process` function.

    Parameters
    ----------
    apikey : str
        VT API key
    entity: str
        The "entity" within the VirusTotal corpus to search. E.g. 
    since_date: int
        The UNIX timestamp to search from the VT corpus. For urls and files, this 
        corresponds to the `fs:` (first seen) and for domains it corresponds to 
        the `creation_date:` search modifier.
    query : str
        the search query
    limit : int
        Max limit to return from the API. Default unlimited / 0. This parameter is passed to the underlying vt-py Client.
    callback : Callable[[self, dict], Coroutine[Any, Any, Any]]
        The asynchronous callback to perform on each result. For maximum portability, the `vt.Object` returned by the underlying vt-py library is turned into a plain `dict`.
    workers : int
        The number of async workers to task for triaging results.
    """
    def __init__(
        self,
        query: str = None,
        apikey: str = None,
        callback: Callable[[dict], Coroutine[Any, Any, Any]] | None = None,
        limit: int = 0,
        entity: Literal["file", "domain", "url", "ip"] = "file",
        since_date: Optional[int] = None,
        workers: Optional[int] = 5,
        **kwargs,
    ) -> None:
        super().__init__(query=query, apikey=apikey, callback=callback, **kwargs)

        self.limit = limit
        if entity not in ["file", "domain", "url", "ip"]:
            raise VtException(f"entity {entity} is not a valid entity")
        self.entity = entity
        if since_date:
            since = self.construct_date(since_date)
            match self.entity:
                case "file" | "url":
                    self.since = f"fs:{since}+"
                case "domain":
                    self.since = f"creation_date:{since}+"
                case _:
                    raise VtException(
                        f"entity {self.entity} does not support date-based searches"
                    )
        else:
            self.since = ""
        self.query = f"entity:{self.entity} {self.since} ({self.query})"
        self.num_workers = workers

    def construct_date(self, unix_timestamp: int) -> str:
        """construct a date string from unix timestamp. The date string is in YYYY-mm-ddTHH:MM:SS format compatible with VirusTotal search"""
        ts_i = unix_timestamp / 1e3

        return datetime.fromtimestamp(ts_i, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")

    async def search(self):
        """method to actually conduct the search"""
        try:
            async with vt.Client(apikey=self.apikey, trust_env=True) as session:
                # note: vt-py wraps aiohttp under the hood.
                self.session = session
                processors = [
                    asyncio.create_task(self.process()) for _ in range(self.num_workers)
                ]
                _results = session.iterator(
                    vt_base, params={"query": self.query}, limit=self.limit
                )
                async for _result in _results:
                    d = json.loads(
                        json.dumps(_result.to_dict(), cls=vt.object.UserDictJsonEncoder)
                    )
                    await self.results.put(d)
                for _stoptoken in [None for _ in range(self.num_workers)]:
                    await self.results.put(_stoptoken)
                await asyncio.gather(*processors)
        except asyncio.exceptions.CancelledError:
            print("VIRUSTOTAL: search cancelled")
        finally:
            if self.session:
                # note: vt-py specific method.
                await self.session.close_async()

        print(f"VIRUSTOTAL: done with search {self.query}")