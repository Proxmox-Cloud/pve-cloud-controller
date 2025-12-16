from kubernetes import client, config, watch
import time
from pprint import pformat
import os
from sqlalchemy import select, create_engine
from sqlalchemy.orm import Session
from pve_cloud.orm.alchemy import AcmeX509
import logging


logging.basicConfig(level=getattr(logging, os.getenv("LOG_LEVEL", "INFO").upper()))
logger = logging.getLogger("cloud-watcher")


def watch_namespaces():
    config.load_incluster_config()
    v1 = client.CoreV1Api()
    
    # todo: this is not perfectly clean
    initial_list = v1.list_namespace(limit=1)
    resource_version = initial_list.metadata.resource_version

    w = watch.Watch()

    for event in w.stream(v1.list_namespace, resource_version=resource_version, timeout_seconds=60):
        # here we only want to exclude the defualt namespaces, even if we dont want to apply mirroring
        # we still want to apply tls
        if event['object'].metadata.name in os.getenv("EXCLUDE_BASE_NAMESPACES").split(","):
            logger.debug("excluding ns")
            logger.debug(event['object'].metadata.name)
            continue
        
        logger.debug(pformat(event))

        if event['type'] == 'ADDED':
            # insert cluster-tls secret
            # todo: print warning if nothing is defined and continue => for e2e scenario
            engine = create_engine(os.getenv("PG_CONN_STR"))
            with Session(engine) as session:
                stmt = select(AcmeX509).where(AcmeX509.stack_fqdn == os.getenv("STACK_FQDN"))
                cert = session.scalars(stmt).first()

            if not cert:
                logger.info(f"No certificate found for {os.getenv('STACK_FQDN')}")
                continue

            secret = client.V1Secret(metadata=client.V1ObjectMeta(name='cluster-tls'),
                type="kubernetes.io/tls",
                string_data=cert.k8s
            )

            v1.create_namespaced_secret(namespace=event['object'].metadata.name, body=secret)


def main():
    while True:
        try:
            logger.debug("watching namespaces")
            watch_namespaces()
        except Exception as e:
            logger.error(f"[!] Error in watcher loop: {e} - {type(e)}")
            time.sleep(5)
