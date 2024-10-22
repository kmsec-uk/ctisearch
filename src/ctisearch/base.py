#! /usr/bin/env python3.11
from typing import Any, Callable, Coroutine, Optional
import asyncio
import aiohttp

class SearchException(Exception):
    """Encapsulates all errors retrieving data from searches"""

    def __init__(self, message):
        self.message = message
        super().__init__(self.message)


class BaseSearch:
    def __init__(self, query: str = None, apikey: str = None, callback: Optional[Callable[[dict], Coroutine[Any, Any, Any]]] =None, **kwargs) -> None:
        if not apikey:
            raise SearchException(
                f"No APIKey was specified for search {query}"
            )
        
        self.apikey: str = apikey
        self.query: str = query

        # callback is the function to call for each result.
        # self.callback = callback if callback else self.default_callback
        self.callback = callback if callback else self.default_callback
        
        self.session: None | aiohttp.ClientSession = None
        # results queue items are what the callback is performed on
        self.results = asyncio.Queue()
        self.total: int = 0
        # resolved marks the number of results processed.
        self.resolved = 0
        # processed is the property to access after results have been processed by the callback. it is the final product of the class.
        self.processed = []
        self.meta = kwargs
    
    async def default_callback(self, instance, d: dict) -> None:
        """default callback to call for results from a search - default to returning the full dict and appending self tags
        Parameters
        ----------
        instance : class reference
            a reference to the class instance from where this callback was called from
        d : dict
            the dict to process
        """
        d["meta"] = self.meta
        return d
    
    async def process(self):
        """Processor function that retrieves an item from the results queue until the queue yields `None`"""
        while True:
            try:
                result = await self.results.get()
                # the signal for end of queue is `None`
                if result is None:
                    return self.results.task_done()
                # callback is called here. we only add to self.processed if the callback returns a Truthy value
                if processed_result := await self.callback(self, result):
                    # the callback can return a list which is spread into self.processed
                    if isinstance(processed_result, list):
                        self.processed.extend(processed_result)
                    # if not list, append the result directly to the list.
                    else:
                        self.processed.append(processed_result)

                self.resolved += 1
            except asyncio.exceptions.CancelledError:
                break