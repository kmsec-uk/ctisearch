#! /usr/bin/env python3.11
import asyncio
import time
from json import JSONDecodeError
from typing import Any, Callable, Coroutine, Optional
from .base import SearchException, BaseSearch

import aiohttp

urlscan_base_url = "https://urlscan.io/api/v1/search/"

# https://urlscan.io/user/
# rate limit is calculated per minute at the level designated in the user profile

MAX_REQUESTS = 120
RATE_LIMIT_INTERVAL = 60 / MAX_REQUESTS


class UrlscanException(SearchException):
    """Encapsulates all errors retrieving data from urlscan.io"""

    def __init__(self, message):
        self.message = message
        super().__init__(self.message)

class UrlscanSearch(BaseSearch):
    """
    A flexible class to represent a search of urlscan.io search API.

    With this class, you can initiate a search on urlscan and optionally retrieve the full task results for that search.

    When results are retrieved, you can use a callback function to process each result.

    For example:

    ```
    async def test():

    apikey = os.environ.get("URLSCAN_API_KEY")

    async def my_callback(d: dict):
        '''My custom callback for processing urlscan.io reports'''
        iocs = []
        print(f"task url: {d['task']['url']}")
        for request_dict in d["data"]["requests"]:
            if (mal_js := request_dict['request']['request']['url']).endswith(".js"):
                iocs.append(mal_js)

        return iocs

    s = UrlscanSearch(
        query="domain:kmsec.uk",
        apikey=apikey,
        get_task_details=True,
        callback=my_callback,
    )

    await s.search()

    print(f"my callback processed {s.resolved} results, and I have gathered {len(s.processed)} iocs:")
    print(("\n").join(f"\t* {ioc}" for ioc in s.processed))

    if __name__ == "__main__":
        asyncio.run(test())

    ```
    Parameters
    ----------
    apikey : str
        urlscan.io API key
    query : str
        The elasticsearch-compatible query string. Example `domain:kmsec.uk`
    since_date : Optional[int]
        optional - A date format supported in the Elasticsearch query language, in string format.
        You can use unix timestamp here in seconds or miliseconds. Example `1727860846`
    get_task_details : Optional[bool]
        optional, default False - A boolean switch whether to get the full urlscan.io scan task results for each query match.
    callback : Callable[[dict], Coroutine[Any, Any, Any]]
        optional, The *async* callback function to perform on each result.
        The callback function should take two positional parameters - the class instance and the dict of each result from the search (or the dict of each task detail if `get_task_details` is set)
        If the callback function return value is Truthy, the result is appended (or extended, in the case of a return type of `list`) to the `processed` attribute.
        If the callback function return value is Falsy, nothing is done with the result.
        If you need to enrich results or process them using filesystem or API calls, leveraging a custom callback function here will be beneficial as this is done asynchronously by multiple workers.
    workers : Optional[int]
        optional, default 5. The number of async workers to deploy. 5 is usually enough.

    Attributes
    ----------
    processed : list
        The results after you have processed all results. If a callback function is not specified, this will contain `dict`s of urlscan search results (or each task record, if `get_task_details` is set to `True`)
    resolved : int
        The number of results from the search triaged by the internal `process` function.
    """

    def __init__(
        self,
        query: str = None,
        apikey=None,
        callback: Callable[[dict], Coroutine[Any, Any, Any]] = None,
        since_date: Optional[int] = None,
        get_task_details: Optional[bool] = False,
        workers: Optional[int] = 5,
        **kwargs
    ) -> None:
        
        # initialise the base class
        super().__init__(query=query, apikey=apikey, callback=callback, **kwargs)

        self.headers: dict = {"Content-Type": "application/json", "API-Key": apikey}
        self.since_date: str | None = str(since_date) if since_date else None
        # If get_task_details is `True`, the search will return the full task results rather than the non-detailed one.
        self.get_task_details = get_task_details

        # rate limiter
        # 120 concurrent requests limit
        self.rate_limiter = asyncio.Semaphore(MAX_REQUESTS)
        # time of last request
        self.last_request_time = 0

        if get_task_details:
            # report_queue is the queue of reports to retrieve.
            self.report_queue = asyncio.Queue()

        # _search_count is used internally to mark the progress of a search. This is used to page through results of urlscan.
        self._search_count = 0
        # search after is used internally to page through urlscan results.
        self._search_after = None

        # we set a static number of workers
        self.num_workers = workers


    async def rate_limit(self):
        # Wait for the semaphore (based on MAX_REQUESTS per rolling minute)
        await self.rate_limiter.acquire()

        # calculate how long to wait since the last request
        elapsed_time = time.time() - self.last_request_time
        wait_time = max(0, RATE_LIMIT_INTERVAL - elapsed_time)

        if wait_time > 0:
            await asyncio.sleep(wait_time)

        # store the current time for rate limiting
        self.last_request_time = time.time()

        # release the semaphore after a delay (in the background)
        asyncio.create_task(self.release_semaphore())

    async def release_semaphore(self):
        """"""
        await asyncio.sleep(60)  # sleep for the full minute before releasing
        self.rate_limiter.release()

    async def get_report(self):
        """
        Only called if self.get_task_details is `True`
        This function gets a report url from self.report_queue, retrieves the resulting urlscan report, and pushes it to the result queue.
        """
        while True:
            try:
                report_url = await self.report_queue.get()
                # the signal for end of queue is `None`
                if report_url is None:
                    # if we are done retrieving reports, we need to signal the end of the result queue as well.
                    # only need to do this once per worker.
                    await self.results.put(None)
                    return self.report_queue.task_done()

                # enforce the rate limit
                await self.rate_limit()

                # retrieve the result
                async with self.session.get(
                    report_url, headers=self.headers
                ) as response:
                    j = await response.json()
                    if not response.ok:
                        raise UrlscanException(
                            f"{response.status} from urlscan.io while retrieving {report_url}: {j}"
                        )
                    # put the result in the result queue
                    await self.results.put(j)
                    # end task
                    self.report_queue.task_done()

            except aiohttp.ContentTypeError:
                raise UrlscanException(
                    f"{response.status} from urlscan.io with unexpected content type {response.content_type}"
                )

            except asyncio.exceptions.CancelledError:
                break

    async def get_results(self):
        """Retrieve the results from the search query"""
        await self.rate_limit()
        params = {
            "q": f"date:>{self.since_date} AND ({self.query})"
            if self.since_date
            else self.query
        }

        if self._search_after:
            params["search_after"] = self._search_after

        async with self.session.get(
            urlscan_base_url, params=params, headers=self.headers
        ) as response:
            if not response.ok:
                try:
                    j = await response.json()
                    raise UrlscanException(f"{response.status} from urlscan.io: {j}")
                except aiohttp.ContentTypeError:
                    raise UrlscanException(
                        f"{response.status} from urlscan.io with unexpected content type {response.content_type}"
                    )
                except JSONDecodeError:
                    raise UrlscanException(
                        f"{response.status} from urlscan.io, invalid JSON response."
                    )
            j = await response.json()
            # print the total
            if not self.total:
                self.total = j["total"]
                print(
                    f"URLSCAN: urlscan reports {self.total} results for search {self.query}"
                )

            _results = j["results"]

            print(f"URLSCAN: retrieved {len(_results)} for search {self.query}")

            for result in _results:
                # if we have been asked to retrieve the report details, push the result url to the queue.
                if self.get_task_details:
                    await self.report_queue.put(result["result"])
                else:
                    await self.results.put(result)
            self._search_count += len(_results)
            # if we have not processed all the results
            if self._search_count < self.total:
                # set the `search_after` param
                self._search_after = (",").join(str(x) for x in _results[-1]["sort"])
                return False
            else:
                # we are finished retrieving pages from the search
                # push stop tokens to the relevant queue.
                if self.get_task_details:
                    # We push `None` to the queue to signal the end.
                    for _stoptoken in [None for _ in range(self.num_workers)]:
                        await self.report_queue.put(_stoptoken)
                else:
                    # We push `None` to the queue to signal the end.
                    for _stoptoken in [None for _ in range(self.num_workers)]:
                        await self.results.put(_stoptoken)
                return True

    async def search(self):
        try:
            async with aiohttp.ClientSession(trust_env=True) as session:
                self.session = session
                # setup workers
                tasks = []
                if self.get_task_details:
                    tasks += [
                        asyncio.create_task(self.get_report())
                        for _ in range(self.num_workers)
                    ]
                tasks += [
                    asyncio.create_task(self.process()) for _ in range(self.num_workers)
                ]

                # infinitely loop until we have retrieved all results for the search
                while True:
                    _finished = await self.get_results()

                    if _finished:
                        break

                await asyncio.gather(*tasks)

        except asyncio.exceptions.CancelledError:
            print("URLSCAN: Search cancelled")

        finally:
            if self.session:
                await self.session.close()

        print(f"URLSCAN: done with search {self.query}")