import base64
import logging
import os
import pickle
import queue
import socket
import ssl
import struct

from flask import Flask, jsonify, request
from flask_socketio import ConnectionRefusedError, SocketIO, emit
from pve_cloud.lib.backup_rpc import Command
from pve_cloud.orm.alchemy import AcmeX509, ProxmoxCloudSecrets
from sqlalchemy import create_engine, select, update
from sqlalchemy.orm import Session

import pve_cloud_ctrl.funcs as funcs

logging.basicConfig(level=getattr(logging, os.getenv("LOG_LEVEL", "INFO").upper()))
logger = logging.getLogger("multi-cloud")

app = Flask(__name__)

log_debug = os.getenv("LOG_LEVEL") == "DEBUG"
socketio = SocketIO(
    app, logger=log_debug, engineio_logger=log_debug, ping_interval=60, ping_timeout=60
)  # increase for io blocking ops


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
        # we pass the public ip of the peer aswell as ignore any cluster cert checks
        # and only validate against the domains of the cloud
        funcs.set_ingress_dyn_dns(
            bind_domains,
            ingress_update["host"],
            address=ingress_update["address"],
            skip_cluster_cert_check=True,
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
                    "cloud_domain": secret.cloud_domain,
                }
            )

    return jsonify(alertmanagers)


# gotify application registration
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
            return jsonify(
                {"gotify_present": True, "gotify_access": gotify_master.secret_data}
            )

    return jsonify({"gotify_present": False})


# vlogs basic auth for master vlselect aggregation
@app.route("/get-vlselect-auth", methods=["GET"])
def get_vlselect_auth():
    auth = request.headers.get("Authorization")
    if not auth or auth.split()[1] != os.getenv("MC_TOKEN"):
        return "Unauthorized", 401

    engine = create_engine(os.getenv("PG_CONN_STR"))
    with Session(engine) as session:
        stmt = select(ProxmoxCloudSecrets).where(
            ProxmoxCloudSecrets.cloud_domain == os.getenv("PVE_CLOUD_DOMAIN"),
            ProxmoxCloudSecrets.secret_name
            == f"{os.getenv('PVE_CLOUD_DOMAIN')}-vlogs-storage-node",
        )
        vlselect_auth = session.scalars(stmt).first()
        if vlselect_auth:
            return jsonify(
                {"auth_present": True, "vlselect_auth": vlselect_auth.secret_data}
            )

    return jsonify({"auth_present": False})


# vlogs client discovery
@app.route("/get-victoria-clients", methods=["GET"])
def get_victoria_clients():
    auth = request.headers.get("Authorization")
    if not auth or auth.split()[1] != os.getenv("MC_TOKEN"):
        return "Unauthorized", 401

    victoria_clients = []

    engine = create_engine(os.getenv("PG_CONN_STR"))
    with Session(engine) as session:
        stmt = select(ProxmoxCloudSecrets).where(
            ProxmoxCloudSecrets.cloud_domain == os.getenv("PVE_CLOUD_DOMAIN"),
            ProxmoxCloudSecrets.secret_type == "vlogs-storage-node",
        )
        vlog_clients = session.scalars(stmt).all()
        for client in vlog_clients:
            victoria_clients.append(
                {
                    "secret_name": client.secret_name,
                    "secret_data": client.secret_data,
                    "cloud_domain": client.cloud_domain,
                }
            )

    return jsonify(victoria_clients)


@app.route("/get-external-stack-acme/<string:stack_fqdn>", methods=["GET"])
def get_external_stack_acme_crt(stack_fqdn):
    auth = request.headers.get("Authorization")
    if not auth or auth.split()[1] != os.getenv("EXTERNAL_MC_TOKEN"):
        return "Unauthorized", 401

    engine = create_engine(os.getenv("PG_CONN_STR"))
    with Session(engine) as session:
        stmt = select(AcmeX509).where(AcmeX509.stack_fqdn == stack_fqdn)

        acme_cert = session.scalars(stmt).first()
        if acme_cert and acme_cert.k8s:
            return jsonify(acme_cert.k8s)
        elif acme_cert:
            return "Cert not yet generated!", 202

    return "Cert not found!", 404


# socket io backup funneling
bdd_connections = {}  # each websocket client gets a dedicated connection here


def recv_exactly(sock, n):
    data = bytearray()

    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise ConnectionError("Backend disconnected")
        data.extend(chunk)

    return bytes(data)


@socketio.on("connect")
def socketio_connect(auth):
    logger.info("connected")
    logger.info(auth)
    if not auth or auth.get("token") != os.getenv("EXTERNAL_MC_TOKEN"):
        raise ConnectionRefusedError("Unauthorized!")

    # client simply has to send the bdd target stack name and the token
    # then we use the clouds internal discovery to connect to the backup server
    if not "bdd_stack_name" in auth:
        raise ConnectionRefusedError("BDD stack name missing!")

    bdd_stack_name = auth["bdd_stack_name"]

    engine = create_engine(os.getenv("PG_CONN_STR"))
    with Session(engine) as session:
        stmt = select(ProxmoxCloudSecrets).where(
            ProxmoxCloudSecrets.cloud_domain == os.getenv("PVE_CLOUD_DOMAIN"),
            ProxmoxCloudSecrets.secret_name == f"{bdd_stack_name}-bdd-tls-discovery",
        )
        bdd_discovery = session.scalars(stmt).first()

    if not bdd_discovery:
        raise ConnectionRefusedError("No discovery secret for bdd stack name!")

    bdd_server_ip = bdd_discovery.secret_data["server_int_ip"]

    # proxy connect
    ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ssl_ctx.check_hostname = False
    ssl_ctx.verify_mode = ssl.CERT_NONE

    raw_sock = socket.create_connection((bdd_server_ip, 8085))

    backend = ssl_ctx.wrap_socket(raw_sock)
    bdd_connections[request.sid] = backend


archive_worker_queues = {}


@socketio.on("disconnect")
def socketio_disconnect(auth):
    logger.info(f"socket disconnected {request.sid}")
    backend = bdd_connections.pop(request.sid, None)
    worker_queue = archive_worker_queues.pop(request.sid, None)

    if backend:
        try:
            backend.shutdown(socket.SHUT_WR)  # gentle shutdown
            backend.close()
        except OSError as e:
            logger.warn(f"Error on backend shutdown {e}")

    if worker_queue:
        worker_queue[0].put_nowait(None)  # that should cancel the worker at some point


def receive_archive_signal(backend):
    signal = recv_exactly(backend, 1)

    if signal == b"\x02":
        logger.debug("waiting for log, continue wait keepalive received.")
        return {"status": "WAIT"}

    if signal != b"\x01":
        logger.error("Received incorrect go signal!")
        return {
            "status": "ERR",
            "error": "INCORRECT_GO_SIGNAL",
        }

    logger.debug("received correct go!")
    return {
        "status": "ACQUIRED",
    }


# this proxy call will ask the server to init a backup process
# which the server will respond with ok as soon as it accuried a lokc
# on the backup repository
@socketio.on("archive_init")
def bdd_init_archive(request_dict):
    backend = bdd_connections[request.sid]

    backend.sendall(struct.pack("B", Command.ARCHIVE.value))

    logger.info("request_dict: %s", request_dict)
    data = pickle.dumps(request_dict)

    logger.debug(f"sending data {len(data)}")
    backend.sendall(struct.pack("!I", len(data)))
    backend.sendall(data)

    # init background worker thats used for async processing
    # in backup_chunk
    q = queue.Queue(maxsize=8)  # max 8x 4mb chunks in buffer

    def backup_writer():
        while True:
            chunk = q.get()

            try:
                if chunk is None:
                    return  # finished

                logger.debug(f"worker sending chunk {len(chunk)}")

                backend.sendall(struct.pack("!I", len(chunk)))
                backend.sendall(chunk)
            finally:
                q.task_done()  # counter -1

    worker_handle = socketio.start_background_task(backup_writer)

    archive_worker_queues[request.sid] = (q, worker_handle)

    return receive_archive_signal(backend)


@socketio.on("wait_archive")
def bdd_wait_archive():
    backend = bdd_connections[request.sid]

    return receive_archive_signal(backend)


@socketio.on("backup_chunk")
def backup_chunk(data):
    logger.debug(f"received backup chunk {len(data)}")
    queue, _ = archive_worker_queues.get(request.sid)

    queue.put(data)

    return None


@socketio.on("backup_eof")
def backup_eof():
    backend = bdd_connections.get(request.sid)
    queue, worker = archive_worker_queues.get(request.sid)
    logger.debug("received backup eof")

    # put queue exit signal
    queue.put(None)
    logger.debug("put none exit signal")

    # first wait for the queue to drain and the worker to exit
    queue.join()
    logger.debug("joined queue")
    worker.join()
    logger.debug("joined worker")
    archive_worker_queues.pop(request.sid, None)

    # send eof to our target server
    backend.sendall(struct.pack("!I", 0))

    logger.debug("backup eof send")
    return None


@socketio.on("bdd_meta")
def bdd_meta(data):
    backend = bdd_connections.get(request.sid)

    backend.sendall(struct.pack("B", data["command"]))

    meta_pickled = pickle.dumps(data["meta_dict"])

    backend.sendall(struct.pack("!I", len(meta_pickled)))
    backend.sendall(meta_pickled)

    return None


@socketio.on("list_backup_details")
def bdd_backup_details(timestamp):
    backend = bdd_connections.get(request.sid)

    backend.sendall(struct.pack("B", Command.LIST_BACKUP_DETAILS.value))

    backend.sendall((timestamp + "\n").encode())

    dict_size = struct.unpack("!I", recv_exactly(backend, 4))[0]
    metas = pickle.loads(recv_exactly(backend, dict_size))

    # first we group metas
    k8s_stack = metas[0]["stack"]

    logger.info(f"k8s stack {k8s_stack}")

    # query the server for backup secrets
    backend.sendall((k8s_stack + "\n").encode())

    # read the meta information
    dict_size = struct.unpack("!I", recv_exactly(backend, 4))[0]
    stack_meta = pickle.loads(recv_exactly(backend, dict_size))

    backend.sendall("##BRCTL-DONE\n".encode())

    return {"metas": metas, "stack_meta": stack_meta}


@socketio.on("list_backups")
def bdd_list_backups():
    backend = bdd_connections.get(request.sid)

    backend.sendall(struct.pack("B", Command.LIST_BACKUPS.value))

    dict_size = struct.unpack("!I", recv_exactly(backend, 4))[0]
    archives = pickle.loads(recv_exactly(backend, dict_size))

    return {"archives": archives}


@socketio.on("init_restore")
def bdd_init_restore(timestamp):
    backend = bdd_connections.get(request.sid)

    backend.sendall(struct.pack("B", Command.RESTORE_PROCEDURE.value))

    backend.sendall((timestamp + "\n").encode())

    dict_size = struct.unpack("!I", recv_exactly(backend, 4))[0]
    metas = pickle.loads(recv_exactly(backend, dict_size))

    metas_grouped_by_ns = {}

    for meta in metas:
        if meta["namespace"] not in metas_grouped_by_ns:
            metas_grouped_by_ns[meta["namespace"]] = []

        metas_grouped_by_ns[meta["namespace"]].append(meta)

    dict_size = struct.unpack("!I", recv_exactly(backend, 4))[0]
    stack_meta = pickle.loads(recv_exactly(backend, dict_size))

    namespace_secret_dict = pickle.loads(
        base64.b64decode(stack_meta["namespace_secret_dict_b64"])
    )

    return pickle.dumps(
        {
            "metas_grouped_by_ns": metas_grouped_by_ns,
            "namespace_secret_dict": namespace_secret_dict,
        }
    )


@socketio.on("init_request")
def bdd_init_request(request_dict):
    backend = bdd_connections.get(request.sid)
    logger.info("received init_request: %s", request_dict)

    # this requests a stream of the actual backup raw image
    backend.sendall(request_dict["archive"].encode())
    backend.sendall(request_dict["artifact"].encode())

    return None


# needs to be called after init_request
@socketio.on("request_chunk")
def bdd_request_chunk():
    backend = bdd_connections.get(request.sid)

    dict_size = struct.unpack("!I", recv_exactly(backend, 4))[0]
    if dict_size == 0:
        return None  # EOF

    return recv_exactly(backend, dict_size)


@socketio.on("request_done")
def bdd_request_done():
    # signal that the backup server can stop serving and close
    backend = bdd_connections.get(request.sid)

    backend.sendall("##BRCTL-DONE\n".encode())
    return None


def main():
    socketio.run(app, host="0.0.0.0", port=80)  # change to mainstream 5000?
