import logging
import os
import time
from pprint import pformat

from kubernetes import client, config, watch
from pve_cloud.orm.alchemy import AcmeX509
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

logging.basicConfig(level=getattr(logging, os.getenv("LOG_LEVEL", "INFO").upper()))
logger = logging.getLogger("cloud-watcher")


def watch_pods():
    config.load_incluster_config()
    v1 = client.CoreV1Api()

    # todo: this is not perfectly clean
    initial_list = v1.list_pod_for_all_namespaces(limit=1)
    resource_version = initial_list.metadata.resource_version

    w = watch.Watch()

    for event in w.stream(
        v1.list_pod_for_all_namespaces,
        resource_version=resource_version,
        timeout_seconds=60,
    ):
        # we only want to watch pods in namespaces that have mirroring active
        if event["object"].metadata.name in os.getenv(
            "EXCLUDE_MIRROR_NAMESPACES"
        ).split(","):
            logger.debug("excluding ns")
            logger.debug(event["object"].metadata.name)
            continue

        logger.debug(pformat(event))

        # we watch pods for going into phase running
        # this means the mirroring is done and we can push the artifact fully into our
        # cloud-mirror repository retagged


def main():
    while True:
        try:
            logger.debug("watching namespaces")
            watch_pods()
        except Exception as e:
            logger.error(f"[!] Error in watcher loop: {e} - {type(e)}")
            time.sleep(5)
