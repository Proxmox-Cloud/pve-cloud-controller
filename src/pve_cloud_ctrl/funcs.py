import fnmatch
import json
import logging
import os

import boto3
import dns.query
import dns.rcode
import dns.tsigkeyring
import dns.update
from botocore.exceptions import ClientError
from pve_cloud.orm.alchemy import BindDomains
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

logging.basicConfig(level=getattr(logging, os.getenv("LOG_LEVEL", "INFO").upper()))
logger = logging.getLogger("cloud-funcs")


# init boto3 client if os vars are defined
route53_key_id = os.getenv("ROUTE53_ACCESS_KEY_ID")
route53_secret_key = os.getenv("ROUTE53_SECRET_ACCESS_KEY")

if route53_key_id and route53_secret_key:
    logger.debug("route53 env variables are defined, initializing boto client.")
    if os.getenv("ROUTE53_ENDPOINT_URL"):
        boto_client = boto3.client(
            "route53",
            region_name=os.getenv("ROUTE53_REGION"),
            endpoint_url=os.getenv("ROUTE53_ENDPOINT_URL"),
            aws_access_key_id=route53_key_id,
            aws_secret_access_key=route53_secret_key,
        )
    else:
        # use default endpoint (no e2e testing)
        boto_client = boto3.client(
            "route53",
            region_name=os.getenv("ROUTE53_REGION"),
            aws_access_key_id=route53_key_id,
            aws_secret_access_key=route53_secret_key,
        )


# load the cluster cert conf
with open("/etc/controller-conf/cluster_cert_entries.json", "r") as f:
    cluster_cert_entries = json.load(f)

# load externally exposed domains
with open("/etc/controller-conf/external_domains.json", "r") as f:
    external_domains = json.load(f)


def validate_host_allowed(host):
    allowed = False
    for entry in cluster_cert_entries:
        zone = entry["zone"]

        for name in entry["names"]:
            if fnmatch.fnmatch(host, f"{name}.{zone}"):
                allowed = True
                break

        if entry["apex_zone_san"] and zone == host:
            # if there was an apex san created it covers a host that equals the zone
            allowed = True

    # return errors
    return allowed


def host_exposed(host):
    exposed = False
    for entry in external_domains:
        zone = entry["zone"]

        for name in entry["names"]:
            if fnmatch.fnmatch(host, f"{name}.{zone}"):
                exposed = True
                break

        if entry["expose_apex"] and zone == host:
            # if there was an apex san created it covers a host that equals the zone
            exposed = True

    return exposed


def get_bind_domains():
    engine = create_engine(os.getenv("PG_CONN_STR"))
    with Session(engine) as session:
        stmt = select(BindDomains)
        domains = session.execute(stmt).scalars().all()

    logger.debug([domain.domain for domain in domains])
    return domains


def get_ext_domains():
    if not (route53_key_id and route53_secret_key):
        logger.debug("returning none for get_ext_domains")
        return None  # function will handle

    # only implemented for route53 at the moment
    hosted_zones = boto_client.list_hosted_zones()["HostedZones"]

    logger.debug(f"num hosted zones found {len(hosted_zones)}")

    return [(zone["Name"], zone["Id"]) for zone in hosted_zones]


def set_ingress_ext_dyn_dns(ext_domains, host):
    cluster_cert_covered = validate_host_allowed(host)
    if not cluster_cert_covered:
        return [f"Host {host} is not covered by the clusters certificate!"]

    if ext_domains is None:
        return []

    if not host_exposed(host):
        return []  # we skip external dns for hosts that are not exposed

    matching_domain = None
    for domain in ext_domains:
        if host.endswith(
            domain[0].removesuffix(".")
        ):  # boto domains are fully quantified
            matching_domain = domain
            break

    if matching_domain is None:
        logger.info(f"No external authoratative domain found for host {host}")
        return []

    try:
        response = boto_client.change_resource_record_sets(
            HostedZoneId=matching_domain[1],
            ChangeBatch={
                "Changes": [
                    {
                        "Action": "UPSERT",  # replace or create
                        "ResourceRecordSet": {
                            "Name": host + ".",
                            "Type": "A",
                            "TTL": 300,
                            "ResourceRecords": [
                                {"Value": os.getenv("EXTERNAL_FORWARDED_IP")}
                            ],
                        },
                    }
                ]
            },
        )

        logger.info("Change submitted: " + response["ChangeInfo"]["Id"])
        return []

    except ClientError as e:
        return [f"Error ext dns update {e.response['Error']}"]


def delete_ingress_ext_dyn_dns(ext_domains, host):
    if ext_domains is None:
        return []

    if not host_exposed(host):
        return []  # we skip external dns for hosts that are not exposed

    matching_domain = None
    for domain in ext_domains:
        if host.endswith(
            domain[0].removesuffix(".")
        ):  # boto domains are fully quantified
            matching_domain = domain
            break

    if matching_domain is None:
        logger.info(f"No external authoratative domain found for host {host}")
        return []

    try:
        response = boto_client.change_resource_record_sets(
            HostedZoneId=matching_domain[1],
            ChangeBatch={
                "Changes": [
                    {
                        "Action": "DELETE",
                        "ResourceRecordSet": {
                            "Name": host + ".",
                            "Type": "A",
                            "TTL": 300,
                            "ResourceRecords": [
                                {"Value": os.getenv("EXTERNAL_FORWARDED_IP")}
                            ],
                        },
                    }
                ]
            },
        )

        logger.info("Change submitted:")
        logger.info(response["ChangeInfo"]["Id"])
        return []

    except ClientError as e:
        logger.info("error deleting ext dns")
        logger.info(e)
        return [f"Error ext dns delete {e.response['Error']}"]


def set_ingress_dyn_dns(bind_domains, host):
    cluster_cert_covered = validate_host_allowed(host)
    if not cluster_cert_covered:
        return [f"Host {host} is not covered by the clusters certificate!"]

    matching_domain = None
    for bind_domain in bind_domains:
        if host.endswith(bind_domain.domain):
            matching_domain = bind_domain.domain
            break

    if matching_domain is None:
        logger.info(f"No authoratative domain found for host {host}")
        return []

    dns_update = dns.update.Update(
        matching_domain,
        keyring=dns.tsigkeyring.from_text(
            {"internal.": os.getenv("BIND_DNS_UPDATE_KEY")}
        ),
        keyname="internal.",
        keyalgorithm="hmac-sha256",
    )

    # set @ if ingress is for apex, else set the host extracted from full host - matching domain
    dns_update.replace(
        "@" if host == matching_domain else host.removesuffix("." + matching_domain),
        300,
        "A",
        os.getenv("INTERNAL_PROXY_FIP"),
    )
    response = dns.query.tcp(dns_update, os.getenv("BIND_MASTER_IP"))

    logger.info(response)
    logger.info(dns.rcode.to_text(response.rcode()))

    if response.rcode() != dns.rcode.NOERROR:
        return [f"Error internal dns update {dns.rcode.to_text(response.rcode())}"]
    else:
        return []


def delete_ingress_dyn_dns(bind_domains, host):
    # check domain exists in bind first
    matching_domain = None
    for bind_domain in bind_domains:
        if host.endswith(bind_domain.domain):
            matching_domain = bind_domain.domain
            break

    if matching_domain is None:
        logger.info(f"No authoratative domain found for host {host}")
        return []

    # create the update object
    dns_update = dns.update.Update(
        matching_domain,
        keyring=dns.tsigkeyring.from_text(
            {"internal.": os.getenv("BIND_DNS_UPDATE_KEY")}
        ),
        keyname="internal.",
        keyalgorithm="hmac-sha256",
    )

    # delete the record
    dns_update.delete(
        "@" if host == matching_domain else host.removesuffix("." + matching_domain),
        "A",
    )

    response = dns.query.tcp(dns_update, os.getenv("BIND_MASTER_IP"))
    logger.info(response)
    logger.info(dns.rcode.to_text(response.rcode()))

    # should always return noerror calling delete on existing zone, even when record doesnt exist
    if response.rcode() != dns.rcode.NOERROR:
        return [f"Error internal dns delete {dns.rcode.to_text(response.rcode())}"]
    else:
        return []
