import asyncio

from mistralai.workflows import run_worker

from sec_swarm.workflow import CveTriageSwarm

if __name__ == "__main__":
    asyncio.run(run_worker([CveTriageSwarm]))
