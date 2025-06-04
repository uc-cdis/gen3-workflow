import asyncio    
from gen3workflow import logger
import request
from fastapi import HTTPException
from starlette.status import HTTP_200_OK, HTTP_500_INTERNAL_SERVER_ERROR
    

async def poll_tes_task(res, url):
    if res.status_code != HTTP_200_OK:
        logger.error(f"TES server error at '{url}': {res.status_code} {res.text}")
        raise HTTPException(res.status_code, res.text)

    # Get the task ID from the TES response
    task_response = res.json()
    task_id = task_response.get("id")
    if not task_id:
        logger.error("No task ID returned from TES server")
        raise HTTPException(HTTP_500_INTERNAL_SERVER_ERROR, "No task ID returned from TES server")

    # Poll the TES server for the task status until it's READY or RUNNING
    max_attempts = 20
    delay_seconds = 1
    for _ in range(max_attempts):
        poll_res = await request.app.async_client.get(url)
        if poll_res.status_code != HTTP_200_OK:
            logger.error(f"TES server error at '{url}': {poll_res.status_code} {poll_res.text}")
            raise HTTPException(poll_res.status_code, poll_res.text)
        poll_body = poll_res.json()
        state = poll_body.get("state")
        if state in ("READY", "RUNNING"):
            break
        await asyncio.sleep(delay_seconds)
    else:
        logger.error(f"TES task {task_id} did not reach READY or RUNNING state after polling")