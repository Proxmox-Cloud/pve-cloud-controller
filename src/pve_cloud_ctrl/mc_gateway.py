import logging
import os

from flask import Flask, jsonify, request
from pve_cloud.orm.alchemy import AcmeX509, ProxmoxCloudSecrets
from sqlalchemy import create_engine, select, update
from sqlalchemy.orm import Session

import pve_cloud_ctrl.funcs as funcs

logging.basicConfig(level=getattr(logging, os.getenv("LOG_LEVEL", "INFO").upper()))
logger = logging.getLogger("multi-cloud")

app = Flask(__name__)


# this method gets called by other clouds controllers when there is an update happening
@app.route("/ingress-ddns-update", methods=["POST"])
def post_ingress_ddns_update():
    auth = request.headers.get("Authorization")
    if not auth or auth.split()[1] != os.getenv("MC_TOKEN"):
        return "Unauthorized", 401

    ingress_update = request.get_json()
    logger.info(ingress_update)

    bind_domains = funcs.get_bind_domains()

    if ingress_update["operation"] == "ADD":
        funcs.set_ingress_dyn_dns(
            bind_domains, ingress_update["host"], ingress_update["address"]
        )
    elif ingress_update["operation"] == "DELETE":
        funcs.delete_ingress_dyn_dns(bind_domains, ingress_update["host"])
    else:
        return f"Unknown operation {ingress_update['operation']}", 400

    return "Update made", 200


# endpoints for remote awx certificate refreshes
@app.route("/get-acme-configs", methods=["GET"])
def get_acme_configs():
    auth = request.headers.get("Authorization")
    if not auth or auth.split()[1] != os.getenv("MC_TOKEN"):
        return "Unauthorized", 401

    all_certs = []
    engine = create_engine(os.getenv("PG_CONN_STR"))
    with Session(engine) as session:
        stmt = select(AcmeX509)
        certs = session.scalars(stmt).all()
        for cert in certs:
            all_certs.append(
                {
                    "stack_fqdn": cert.stack_fqdn,
                    "config": cert.config,
                    "ec_csr": cert.ec_csr,
                    "ec_crt": cert.ec_crt,
                }
            )

    # return certs for awx
    return jsonify(all_certs)


@app.route("/get-acme-account", methods=["GET"])
def get_acme_account():
    auth = request.headers.get("Authorization")
    if not auth or auth.split()[1] != os.getenv("MC_TOKEN"):
        return "Unauthorized", 401

    engine = create_engine(os.getenv("PG_CONN_STR"))
    with Session(engine) as session:
        stmt = select(ProxmoxCloudSecrets).where(
            ProxmoxCloudSecrets.cloud_domain == os.getenv("PVE_CLOUD_DOMAIN"),
            ProxmoxCloudSecrets.secret_type == "cluster-vars",
        )
        cv_record = session.scalars(stmt).first()
        if not cv_record:
            return "cluster-vars secret not found!", 400

        if "acme_contact" not in cv_record.secret_data:
            return "acme_contact not in cluster vars!", 400

        acme_contact = cv_record.secret_data["acme_contact"]

        # uncomment for mock e2e
        # acme_contact = "test"

        stmt = select(ProxmoxCloudSecrets).where(
            ProxmoxCloudSecrets.cloud_domain == os.getenv("PVE_CLOUD_DOMAIN"),
            ProxmoxCloudSecrets.secret_type == "cluster-secrets",
        )

        cs_record = session.scalars(stmt).first()
        if not cs_record:
            return "cluster-secrets secret not found!", 400

        if "acme-account.key" not in cs_record.secret_data:
            return "acme-account.key not in cluster secrets!", 400

        acme_account_key = cs_record.secret_data["acme-account.key"]

    return jsonify({"acme_contact": acme_contact, "acme-account.key": acme_account_key})


@app.route("/post-acme-x509-update", methods=["POST"])
def post_acme_x509_update():
    auth = request.headers.get("Authorization")
    if not auth or auth.split()[1] != os.getenv("MC_TOKEN"):
        return "Unauthorized", 401

    acme_update = request.get_json()
    engine = create_engine(os.getenv("PG_CONN_STR"))
    with Session(engine) as session:
        stmt = (
            update(AcmeX509)
            .where(AcmeX509.stack_fqdn == acme_update["stack_fqdn"])
            .values(ec_crt=acme_update["ec_crt"], k8s=acme_update["k8s"])
        )

        session.execute(stmt)
        session.commit()

    return "Updated", 200


# endpoints for alertmanager discovery
@app.route("/get-client-alertmanagers", methods=["GET"])
def get_client_alertmanagers():
    auth = request.headers.get("Authorization")
    if not auth or auth.split()[1] != os.getenv("MC_TOKEN"):
        return "Unauthorized", 401
    
    alertmanagers = []

    engine = create_engine(os.getenv("PG_CONN_STR"))
    with Session(engine) as session:
        stmt = select(ProxmoxCloudSecrets).where(
            ProxmoxCloudSecrets.cloud_domain == os.getenv("PVE_CLOUD_DOMAIN"),
            ProxmoxCloudSecrets.secret_type == "mon-alertmgr-client",
        )
        ca_secrets = session.scalars(stmt).all()
        for secret in ca_secrets:
            alertmanagers.append(
                {
                    "secret_name": secret.secret_name,
                    "secret_data": secret.secret_data,
                    "cloud_domain": secret.cloud_domain
                }
            )

    return jsonify(alertmanagers)


@app.route("/get-gotify-master", methods=["GET"])
def get_gotify_master():
    auth = request.headers.get("Authorization")
    if not auth or auth.split()[1] != os.getenv("MC_TOKEN"):
        return "Unauthorized", 401
    
    engine = create_engine(os.getenv("PG_CONN_STR"))
    with Session(engine) as session:
        stmt = select(ProxmoxCloudSecrets).where(
            ProxmoxCloudSecrets.cloud_domain == os.getenv("PVE_CLOUD_DOMAIN"),
            ProxmoxCloudSecrets.secret_name == "gotify_admin_pw",
        )
        gotify_master = session.scalars(stmt).first()
        if gotify_master:
            return jsonify({
                "gotify_present": True,
                "gotify_access": gotify_master.secret_data
            })

    return jsonify({
        "gotify_present": False
    })


def main():
    # todo: change to gunicorn / multi threaded
    app.run(host="0.0.0.0", port=80)
