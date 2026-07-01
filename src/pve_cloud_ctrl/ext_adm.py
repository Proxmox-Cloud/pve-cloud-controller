import base64
import json
import logging
import os
from pprint import pformat

from flask import Flask, jsonify, request
from kubernetes import client, config
from kubernetes.client.rest import ApiException

import pve_cloud_ctrl.funcs as funcs
from pve_cloud_ctrl.adm import get_patched_image

logging.basicConfig(level=getattr(logging, os.getenv("LOG_LEVEL", "INFO").upper()))
logger = logging.getLogger("ext-adm")

app = Flask(__name__)

config.load_incluster_config()
v1 = client.CoreV1Api()
net_v1 = client.NetworkingV1Api()


@app.route("/mutate-pod", methods=["POST"])
def mutate_pod():
    admission_review = request.get_json()
    logger.debug(pformat(admission_review))

    uid = admission_review["request"]["uid"]
    pod_spec = admission_review["request"]["object"]
    pod_name = (
        pod_spec["metadata"]["name"]
        if "name" in pod_spec["metadata"]
        else pod_spec["metadata"]["generateName"]
    )
    namespace = admission_review["request"]["namespace"]

    # logic inserts patches here
    patches = []

    insert_mirror_pull_secret = False  # always false for ext adm controller

    # patch the images of all container (either bitnami only / full mirror patch)
    if "initContainers" in pod_spec["spec"]:
        # preprend harbor.vmz.management/mirror repo
        for i, container in enumerate(pod_spec["spec"]["initContainers"]):
            image = container["image"]
            image_patched = get_patched_image(image, insert_mirror_pull_secret)

            if image != image_patched:
                patches.append(
                    {
                        "op": "replace",
                        "path": f"/spec/initContainers/{i}/image",
                        "value": image_patched,
                    }
                )

    # normal containers
    for i, container in enumerate(pod_spec["spec"]["containers"]):
        image = container["image"]
        image_patched = get_patched_image(image, insert_mirror_pull_secret)

        if image != image_patched:
            patches.append(
                {
                    "op": "replace",
                    "path": f"/spec/containers/{i}/image",
                    "value": image_patched,
                }
            )

    # also check if the general cluster-pull-secret with injection annotation is defined
    # this then also needs to be inserted into the pods pull secrets
    insert_cluster_pull_secret = False
    try:
        secret = v1.read_namespaced_secret(
            name="cluster-pull-secret", namespace=namespace
        )

        if (
            secret.metadata.annotations
            and "pve-cloud-pull-secret" in secret.metadata.annotations
            and secret.metadata.annotations["pve-cloud-pull-secret"] == "pod-inject"
        ):
            logger.info(
                f"cluster-pull-secret with correct annotation exists {namespace} - injecting into pod {pod_name}"
            )
            insert_cluster_pull_secret = True

    except ApiException as e:
        if e.status != 404:
            raise  # other than 404 return is undefined behaviour => crash the controller

    # add / create image pull secrets
    if "imagePullSecrets" in pod_spec["spec"]:
        # the pod already has a list of pull secrets, we simply append ours to it

        if insert_cluster_pull_secret:
            patches.append(
                {
                    "op": "add",
                    "path": "/spec/imagePullSecrets/-",
                    "value": {"name": "cluster-pull-secret"},
                }
            )
    else:
        # the pod doesnt have a list, meaning we need to submit a patch with a list of our secrets
        pull_secrets = []

        if insert_cluster_pull_secret:
            pull_secrets.append({"name": "cluster-pull-secret"})

        if pull_secrets:
            patches.append(
                {
                    "op": "add",
                    "path": "/spec/imagePullSecrets",
                    "value": pull_secrets,
                }
            )

    if patches:
        response = {
            "apiVersion": "admission.k8s.io/v1",
            "kind": "AdmissionReview",
            "response": {
                "uid": uid,
                "allowed": True,
                "patchType": "JSONPatch",
                "patch": base64.b64encode(json.dumps(patches).encode("utf-8")).decode(
                    "utf-8"
                ),
            },
        }

        return jsonify(response)

    # fallback
    response = {
        "apiVersion": "admission.k8s.io/v1",
        "kind": "AdmissionReview",
        "response": {
            "uid": uid,
            "allowed": True,  # Allow the request without modifications
        },
    }

    return jsonify(response)


def main():
    # todo: change to gunicorn / multi threaded
    app.run(
        host="0.0.0.0",
        port=443,
        ssl_context=(
            "/etc/tls/tls.crt",  # Path to TLS certificate
            "/etc/tls/tls.key",  # Path to TLS private key
        ),
    )
