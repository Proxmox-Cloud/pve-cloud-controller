import logging
import os
import subprocess
import time
from pprint import pformat

from cachetools import TTLCache
from kubernetes import client, config, watch
from pve_cloud.orm.alchemy import AcmeX509
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

logging.basicConfig(level=getattr(logging, os.getenv("LOG_LEVEL", "INFO").upper()))
logger = logging.getLogger("cloud-watcher")

harbor_host = os.getenv("HARBOR_MIRROR_HOST")


def watch_pods():
    config.load_incluster_config()
    v1 = client.CoreV1Api()

    # todo: this is not perfectly clean
    initial_list = v1.list_pod_for_all_namespaces(limit=1)
    resource_version = initial_list.metadata.resource_version

    w = watch.Watch()

    processed_pods = TTLCache(maxsize=1024, ttl=36000)

    for event in w.stream(
        v1.list_pod_for_all_namespaces,
        resource_version=resource_version,
        timeout_seconds=60,
    ):
        pod = event["object"]

        # we only want to watch pods in namespaces that have mirroring active
        if pod.metadata.namespace in os.getenv("EXCLUDE_MIRROR_NAMESPACES").split(","):
            logger.debug("excluding ns")
            logger.debug(pod.metadata.namespace)
            continue

        logger.info(pod.metadata.name)
        logger.debug(pformat(event))

        # we watch pods for going into phase running
        # this means the mirroring is done and we can push the artifact fully into our
        # cloud-mirror repository retagged
        container_ready = pod.status.container_statuses and all(
            cs.ready for cs in pod.status.container_statuses
        )
        init_container_ready = not pod.status.init_container_statuses or all(
            cs.ready for cs in pod.status.init_container_statuses
        )
        if pod.status.phase == "Running" and container_ready and init_container_ready:

            # only trigger skopeo once
            if pod.metadata.uid in processed_pods:
                continue

            # collect all images of the pod
            images = [c.image for c in pod.spec.containers]

            if pod.spec.init_containers:
                images.extend(c.image for c in pod.spec.init_containers)

            # process images and retag push them to the full cloud-mirror harbor repository
            for image in images:
                if image.startswith(harbor_host):
                    image_splits = image.removeprefix(f"{harbor_host}/").split("/")
                    harbor_repository = image_splits[0]
                    image_stripped = "/".join(image_splits[1:])

                    logger.info(harbor_repository)
                    logger.info(image_stripped)

                    if harbor_repository.endswith("-cache"):
                        # found a cached repository image, we simply use skopeo to copy it to the full mirror
                        # skopeo is smart about reading / writing layers and doesnt use disk
                        command = [
                            "skopeo",
                            "copy",
                            "--src-creds",
                            f"{os.getenv("HARBOR_ADMIN_USER")}:{os.getenv("HARBOR_ADMIN_PASSWORD")}",
                            "--dest-creds",
                            f"{os.getenv("HARBOR_ADMIN_USER")}:{os.getenv("HARBOR_ADMIN_PASSWORD")}",
                            f"docker://{image}",
                            f"docker://{harbor_host}/cloud-mirror/{harbor_repository.removesuffix("-cache")}/{image_stripped}",
                        ]

                        logger.info(command)

                        subprocess.run(command, text=True, check=True)

            # store that we processed the pod
            processed_pods[pod.metadata.uid] = True


def main():
    while True:
        try:
            logger.debug("watching namespaces")
            watch_pods()
        except Exception as e:
            logger.error(f"[!] Error in watcher loop: {e} - {type(e)}", exc_info=True)
            time.sleep(5)
