import logging
import os

from kubernetes import client, config
from kubernetes.client.rest import ApiException
import requests


logging.basicConfig(level=getattr(logging, os.getenv("LOG_LEVEL", "INFO").upper()))
logger = logging.getLogger("external-cron")


def main():
    config.load_incluster_config()
    v1 = client.CoreV1Api()

    response = requests.get(f"https://{os.getenv('MC_GW_HOST')}/get-external-stack-acme/{os.getenv('EXT_STACK_FQDN')}", headers={
        "Authorization": f"Bearer {os.getenv('EXTERNAL_MC_TOKEN')}"
    })
    logger.debug(response)
    
    response.raise_for_status()
    if response.status_code == 202:
        logger.warning(f"Certificate for {os.getenv('EXT_STACK_NAME')} is not yet generated. Please run the awx generation playbooks / check pxc patroni acme_x509 table.")
        return

    cert_k8s_data = response.json()

    logger.info("crt found")
    logger.info(cert_k8s_data)

    namespaces = v1.list_namespace()

    # only cert and mirror is filtered
    for ns in namespaces.items:
        # here we only want to exclude the defualt namespaces, even if we dont want to apply mirroring
        # we still want to apply tls
        if ns.metadata.name in os.getenv("EXCLUDE_TLS_NAMESPACES").split(","):
            logger.debug(f"excluded {ns.metadata.name}")
            continue

        if ns.status.phase != "Active":
            logger.info(
                f"skipping namespace {ns.metadata.name} (status={ns.status.phase})"
            )
            continue

        logger.info(f"processing certs {ns.metadata.name}")
   
        try:
            # patch the cluster tls secret - this will always be a patch since its default functionality of pve cloud
            pr = v1.patch_namespaced_secret(
                name="cluster-tls",
                namespace=ns.metadata.name,
                body={"stringData": cert_k8s_data},
            )
            logger.info("patched")
            logger.info(pr)
        except ApiException as e:
            # incase it doesnt exist try to create it
            if e.status == 404:
                v1.create_namespaced_secret(
                    namespace=ns.metadata.name,
                    body=client.V1Secret(
                        metadata=client.V1ObjectMeta(name="cluster-tls"),
                        type="kubernetes.io/tls",
                        string_data=cert_k8s_data,
                    ),
                )
            else:
                raise

