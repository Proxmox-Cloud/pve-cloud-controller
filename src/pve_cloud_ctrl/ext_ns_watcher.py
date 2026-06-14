import logging
import os
import time
from pprint import pformat

from kubernetes import client, config, watch
import requests

logging.basicConfig(level=getattr(logging, os.getenv("LOG_LEVEL", "INFO").upper()))
logger = logging.getLogger("external-watcher")


def watch_namespaces():
    config.load_incluster_config()
    v1 = client.CoreV1Api()

    # todo: this is not perfectly clean
    initial_list = v1.list_namespace(limit=1)
    resource_version = initial_list.metadata.resource_version

    w = watch.Watch()

    for event in w.stream(
        v1.list_namespace,
        resource_version=resource_version,
        timeout_seconds=60,
        _request_timeout=70,
    ):

        logger.debug(pformat(event))

        if event["type"] == "ADDED":    
            # query the multi cloud gw for a certificate

            response = requests.get(f"https://{os.getenv('MC_GW_HOST')}/get-external-stack-acme/{os.getenv('EXT_STACK_FQDN')}", headers={
                "Authorization": f"Bearer {os.getenv('EXTERNAL_MC_TOKEN')}"
            })
            logger.debug(response)
            
            response.raise_for_status()
            if response.status_code == 202:
                logger.warning(f"Certificate for {os.getenv('EXT_STACK_NAME')} is not yet generated. Please run the awx generation playbooks / check pxc patroni acme_x509 table.")
                continue

            cert_k8s_data = response.json()
            logger.debug(cert_k8s_data)

            # write the certificate into the newly created namespace
            secret = client.V1Secret(
                metadata=client.V1ObjectMeta(name="cluster-tls"),
                type="kubernetes.io/tls",
                string_data=cert_k8s_data,
            )

            v1.create_namespaced_secret(
                namespace=event["object"].metadata.name, body=secret
            )


def main():
    while True:
        try:
            logger.debug("watching namespaces")
            watch_namespaces()
        except Exception as e:
            logger.error(f"[!] Error in watcher loop: {e} - {type(e)}")
            time.sleep(5)
