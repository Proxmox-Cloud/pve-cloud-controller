import os
from kubernetes import client, config
from sqlalchemy import select, create_engine
from sqlalchemy.orm import Session
from pve_cloud.orm.alchemy import AcmeX509
from kubernetes.client.rest import ApiException
import pve_cloud_ctrl.funcs as funcs
import logging

logging.basicConfig(level=getattr(logging, os.getenv("LOG_LEVEL", "INFO").upper()))
logger = logging.getLogger("cloud-cron")


def main():
    config.load_incluster_config()
    v1 = client.CoreV1Api()
    net_v1 = client.NetworkingV1Api()

    # todo: check if defined => otherwise warning and close
    engine = create_engine(os.getenv("PG_CONN_STR"))

    bind_domains = None

    # select bind domains for ingress dns reapply
    if os.getenv("BIND_DNS_UPDATE_KEY") and os.getenv("BIND_MASTER_IP") and os.getenv("INTERNAL_PROXY_FIP"):
        bind_domains = funcs.get_bind_domains()

    ext_domains = funcs.get_ext_domains() # might be none

    # update certs and mirror pull secret
    with Session(engine) as session:
        stmt = select(AcmeX509).where(AcmeX509.stack_fqdn == os.getenv("STACK_FQDN"))
        cert = session.scalars(stmt).first()

    if not cert:
        logger.info(f"No certificate found for {os.getenv("STACK_FQDN")}")
    else:
        logger.info("crt found", cert.k8s)

    namespaces = v1.list_namespace()

    # apply ingress dns for all namespaces
    for ns in namespaces.items:
        logger.info(f"processing ingress {ns.metadata.name}")

        # reapply ingress dns
        if os.getenv("BIND_DNS_UPDATE_KEY") and os.getenv("BIND_MASTER_IP") and os.getenv("INTERNAL_PROXY_FIP"):

            ingresses = net_v1.list_namespaced_ingress(namespace=ns.metadata.name)

            for ingress in ingresses.items:
                logger.info(ingress.metadata.name)
                
                if ingress.spec.rules:
                    for rule in ingress.spec.rules:
                        host = rule.host

                        errors = []
                        errors.extend(funcs.set_ingress_dyn_dns(bind_domains, host)) 
                        errors.extend(funcs.set_ingress_ext_dyn_dns(ext_domains, host))
                        if errors:
                            raise Exception(", ".join(errors))


    # only cert and mirror is filtered
    for ns in namespaces.items:
        # here we only want to exclude the defualt namespaces, even if we dont want to apply mirroring
        # we still want to apply tls
        if ns.metadata.name in os.getenv("EXCLUDE_BASE_NAMESPACES").split(","):
            logger.debug("excluded", ns.metadata.name)
            continue

        logger.info(f"processing certs {ns.metadata.name}")
        if cert:
            try:
                # patch the cluster tls secret - this will always be a patch since its default functionality of pve cloud
                pr = v1.patch_namespaced_secret(
                    name="cluster-tls",
                    namespace=ns.metadata.name,
                    body={"stringData": cert.k8s}
                )
                logger.info("patched", pr)
            except ApiException as e:
                # incase it doesnt exist try to create it
                if e.status == 404:
                    v1.create_namespaced_secret(namespace=ns.metadata.name, body=client.V1Secret(metadata=client.V1ObjectMeta(name='cluster-tls'),
                        type="kubernetes.io/tls",
                        string_data=cert.k8s)
                    )
                else:
                    raise

        # update or create mirror pull secret - might have been toggled on retroactively
        if os.getenv("HARBOR_MIRROR_PULL_SECRET_NAME"):
            mirror_pull_secret = v1.read_namespaced_secret(os.getenv("HARBOR_MIRROR_PULL_SECRET_NAME"), "pve-cloud-controller")
            logger.info("mps", mirror_pull_secret)

            try:
                v1.create_namespaced_secret(namespace=ns.metadata.name, body=client.V1Secret(metadata=client.V1ObjectMeta(name='mirror-pull-secret'),
                    type="kubernetes.io/dockerconfigjson",
                    data=mirror_pull_secret.data)
                )
            except ApiException as e:
                if e.status == 409: # conflict => update the secret
                    v1.patch_namespaced_secret('mirror-pull-secret', namespace=ns.metadata.name, body={"data": mirror_pull_secret.data})
                else:
                    raise