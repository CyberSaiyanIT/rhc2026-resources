"""Container entrypoint: the API/portal on :8000, the website on :8081, and the workers."""
import asyncio
import logging
import threading

import uvicorn

from .app import create_app
from .config import load_config
from .runtime import Workshop
from .splunk import Hec
from .store import SQLiteStore
from .target import create_target
from .workers import start_workers


def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    logging.getLogger("httpx").setLevel(logging.WARNING)
    config = load_config()
    hec = Hec(config)
    workshop = Workshop(config, SQLiteStore(config["db_path"]), sink=hec)
    stop = threading.Event()
    servers = [
        uvicorn.Server(uvicorn.Config(create_app(workshop), host="0.0.0.0", port=8000, access_log=False, log_level="warning")),
        uvicorn.Server(uvicorn.Config(create_target(workshop), host="0.0.0.0", port=8081, access_log=False, log_level="warning")),
    ]
    logging.getLogger("romhack").info("Workshop ready: portal http://localhost:8080, website http://localhost:8081")
    try:
        asyncio.run(_serve(servers, lambda: start_workers(workshop, hec, stop)))
    finally:
        stop.set()


async def _serve(servers, on_started):
    tasks = [asyncio.create_task(server.serve()) for server in servers]
    # Workers send traffic to the website, so start them once both servers listen.
    while not all(server.started for server in servers):
        if any(task.done() for task in tasks):
            break
        await asyncio.sleep(0.1)
    else:
        on_started()
    await asyncio.gather(*tasks)


if __name__ == "__main__":
    main()
