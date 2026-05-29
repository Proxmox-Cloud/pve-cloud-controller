import logging
import os
from pprint import pformat
import pve_cloud_ctrl.funcs as funcs
from pve_cloud.orm.alchemy import AcmeX509
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from flask import Flask, request

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
        funcs.set_ingress_dyn_dns(bind_domains, ingress_update["host"], ingress_update["address"])
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
    
    engine = create_engine(os.getenv("PG_CONN_STR"))
    with Session(engine) as session:
        stmt = select(AcmeX509)
        certs = session.scalars(stmt).all()
    
    # return certs for awx
    
    return "Success", 200


def main():
    # todo: change to gunicorn / multi threaded
    app.run(
        host="0.0.0.0",
        port=80
    )

