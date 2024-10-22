#! /usr/bin/env python3.11
import asyncio
import math
from json import JSONDecodeError
from typing import Any, Callable, Coroutine, Optional
from .base import BaseSearch, SearchException

import aiohttp

shodan_search_endpoint = "https://api.shodan.io/shodan/host/search"


class ShodanException(SearchException):
    """Encapsulates all errors retrieving data from Shodan"""

    def __init__(self, message):
        self.message = message
        super().__init__(self.message)


class ShodanSearch(BaseSearch):
    """
    A Class to represent a search conducted on Shodan. This will retrieve results across all pages for a given search.

    For example:

    ```python
    async def test():
    '''an example'''
    apikey = os.environ.get("SHODAN_API_KEY")
    async def my_callback(instance, d: dict):
        '''my custom processor to extract the cobalt strike watermark only'''
        try:
            return d["cobalt_strike_beacon"]["x64"]["watermark"]
        except KeyError:
            return None

    cobalt_strike = ShodanSearch(query='product:"Cobalt Strike Beacon"',apikey=apikey, fields=["cobalt_strike_beacon"], callback=my_callback)

    await cobalt_strike.search()

    # count watermarks
    counts = {}
    for watermark in cobalt_strike.processed:
        try:
            counts[watermark] += 1
        except KeyError:
            counts[watermark] = 1
    most_prevalent = max(counts, key=counts.get)
    print(f"The most popular Cobalt Strike Watermark is {most_prevalent} with {counts[most_prevalent]} on the internet")


    if __name__ == "__main__":
        asyncio.run(test())

    ```
    Parameters
    ----------
    apikey : str
        shodan API Key. This is required
    query : str
        The search query to perform on shodan
    fields : Optional[list]
        A list of fields. The default behaviour is to pull all fields.
    callback : Callable[[dict], Coroutine[Any, Any, Any]]
        The *async* callback function to perform on each result. The function should take two positional parameters - 1. a reference to the class itself, 2. the dict of the result to process.
        If the return value from this callback function is Truthy, the result will be appended or extended to the `processed` attribute (the latter if the return value is an instance of `list`)

    Attributes
    ----------
    processed : list
        The results after you have processed all results. If a callback function is not specified, this will contain `dict`s of shodan search results
    resolved : int
        The number of results from the search triaged by the internal `process` function.

    """

    def __init__(
        self,
        query: str = None,
        apikey=None,
        fields: Optional[list] = [],
        callback: Callable[[dict], Coroutine[Any, Any, Any]] = None,
        **kwargs
    ) -> None:
        # initialise the base class
        super().__init__(query=query, apikey=apikey, callback=callback, **kwargs)

        # fields is the fields to specify for the output. Optional.
        self.fields: str = ",".join(fields) if fields else []

        # pages is a queue of page numbers
        self.pages = asyncio.Queue()

        self.num_pages: int = 1
        # total is the total number of results advertised by Shodan

        # number of workers to use
        self.num_workers: int = 0

    async def retrieve_page(self):
        """Retrieves a page from the queue of pages and retrieves the results"""
        while True:
            if self.pages.empty():
                break
            try:
                page = await self.pages.get()
                params = {
                    "key": self.apikey,
                    "query": self.query,
                    "minify": "False",
                    "page": page,
                }

                if len(self.fields):
                    params["fields"] = self.fields
                    params["minify"] = "False"

                async with self.session.get(
                    shodan_search_endpoint, params=params
                ) as response:
                    print(f"SHODAN: getting page {page} for {self.query}")
                    # Errors with response or error in results
                    # We don't throw an error on this instance because it could be a
                    if not response.ok:
                        print(
                            f"SHODAN: {response.status} on page {page} of query {self.query}"
                        )
                        self.pages.task_done()
                    j = await response.json()
                    if "error" in j:
                        print(
                            f'SHODAN: {j["error"]} on page {page} of query {self.query}'
                        )
                        self.pages.task_done()
                    if _matches := j["matches"]:
                        for _match in _matches:
                            await self.results.put(_match)
                        self.pages.task_done()
            except asyncio.exceptions.CancelledError:
                break

    async def get_first_page(self) -> list | None:
        """
        Gets the first page of results and
        returns a list of results from shodan

        We need to do this first to:
            * Check if the query is valid
            * Check how many results there are, which establishes the number of pages and consequently workers to setup.
        """
        params = {"key": self.apikey, "query": self.query, "minify": "False", "page": 1}

        if len(self.fields):
            params["fields"] = self.fields
            params["minify"] = "False"

        async with self.session.get(shodan_search_endpoint, params=params) as response:
            # If we have errors retrieving the first page, fail early.
            # Note that any further errors are not thrown but printed.
            if not response.ok:
                try:
                    j = await response.json()
                    raise ShodanException(f"{response.status} from Shodan API: {j}")
                except (aiohttp.ContentTypeError, JSONDecodeError):
                    raise ShodanException(
                        f"{response.status} from Shodan API with unexpected content type {response.content_type}"
                    )

            j = await response.json()

            if "error" in j:
                raise ShodanException(j["error"])

            self.total = int(j["total"])

            # +1 page as array starts at 0

            self.num_pages = int(math.ceil(self.total / 100)) + 1
            print(
                f"SHODAN: there are {self.num_pages} pages with {self.total} results for query {self.query}"
            )
            return j["matches"]

    async def search(self):
        async with aiohttp.ClientSession(trust_env=True) as session:
            self.session = session
            # get first page
            first_page_results = await self.get_first_page()
            if not first_page_results:
                return None
            # add first page results to queue
            for _match in first_page_results:
                await self.results.put(_match)

            # we've already got the first page, so queue up from 2 onwards
            if self.num_pages > 1:
                for page in [_ for _ in range(2, self.num_pages + 1)]:
                    await self.pages.put(page)

            # we want 5 workers max
            self.num_workers = min(5, self.num_pages)
            print(
                f"SHODAN: there are {self.num_workers} workers retrieving and {self.num_workers} processing"
            )
            # setup the result processors
            processors = [
                asyncio.create_task(self.process()) for _ in range(self.num_workers)
            ]
            # setup the result retrievers
            retrievers = [
                asyncio.create_task(self.retrieve_page())
                for _ in range(self.num_workers)
            ]

            await asyncio.gather(*retrievers)
            # Once all retrievers are finished retrieving
            # We push `None` to the queue to signal the end.
            for _stoptoken in [None for _ in range(self.num_workers)]:
                await self.results.put(_stoptoken)

            # wait for all the processors to process
            await asyncio.gather(*processors)
            return print(f"SHODAN: done with query {self.query}")


