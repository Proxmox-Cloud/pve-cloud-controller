from flask import Flask, request, jsonify
import pprint
import json
import base64
from kubernetes import client, config
import os
from kubernetes.client.rest import ApiException
import pve_cloud_ctrl.funcs as funcs
import dns.rcode


app = Flask(__name__)

config.load_incluster_config()
v1 = client.CoreV1Api()

def get_patched_image(image):
    patch_registry = os.getenv("HARBOR_MIRROR_HOST")

    # bitnami legacy rewrite
    if "bitnami/" in image:
        image = image.replace("bitnami/", "bitnamilegacy/")
        
    registry = image.split('/')[0]
    if registry == "quay.io":
        patched_image = f"{patch_registry}/quay-mirror/{image.removeprefix('quay.io/')}"
    elif registry == "public.ecr.aws":
        patched_image = f"{patch_registry}/aws-ecr-mirror/{image.removeprefix('public.ecr.aws/')}"
    elif registry == "ghcr.io":
        patched_image = f"{patch_registry}/github-mirror/{image.removeprefix('ghcr.io/')}"
    elif registry == "docker.io" or '.' not in registry: # default docker hub registry . not in means its path
        # default docker.io
        patched_image = f"{patch_registry}/docker-hub-mirror/{image.removeprefix('docker.io/')}"
    else:
        patched_image = image

    print("orig image: ", image)
    print("patched image: ", patched_image)

    return patched_image


@app.route('/mutate-pod', methods=['POST'])
def mutate_pod():
    admission_review = request.get_json()

    uid = admission_review['request']['uid']
    pod_spec = admission_review['request']['object']
    namespace = admission_review['request']['namespace']

    # need this to exclude the harbor namespace / system namespaces
    exclude_namespace = False
    if os.getenv("EXCLUDE_ADM_NAMESPACES"):
        if namespace in os.getenv("EXCLUDE_ADM_NAMESPACES").split(','):
            print("exluding namespace")
            exclude_namespace = True

    pprint.pprint(admission_review)

    # pods only get patched to the mirror repository if its actually defined
    if os.getenv("HARBOR_MIRROR_HOST") and os.getenv("HARBOR_MIRROR_PULL_SECRET_NAME") and not exclude_namespace:
        try:
            # check if the secret exists
            mirror_pull_secret = v1.read_namespaced_secret(os.getenv("HARBOR_MIRROR_PULL_SECRET_NAME"), namespace)
            print("secret exists")
        except ApiException as e:
            if e.status == 404: # secret doesnt exist yet, create it
                # read secret from cloud controller namespace
                mps_controller = v1.read_namespaced_secret(os.getenv("HARBOR_MIRROR_PULL_SECRET_NAME"), "pve-cloud-controller")

                secret = client.V1Secret(metadata=client.V1ObjectMeta(name=os.getenv("HARBOR_MIRROR_PULL_SECRET_NAME")),
                    type="kubernetes.io/dockerconfigjson",
                    data=mps_controller.data
                )
                v1.create_namespaced_secret(namespace=namespace, body=secret)
                print("created mps")

        # patch the pods images to point to our harbor mirror
        patches = []

        patched_image = False

        if 'initContainers' in pod_spec['spec']:
            # preprend harbor.vmz.management/mirror repo
            for i, container in enumerate(pod_spec['spec']['initContainers']):
                image = container['image']
                image_patched = get_patched_image(image)
                
                if image != image_patched:
                    patches.append({
                        "op": "replace",
                        "path": f"/spec/initContainers/{i}/image",
                        "value": image_patched
                    })
                    patched_image = True

        # normal containers
        for i, container in enumerate(pod_spec['spec']['containers']):
            image = container['image']
            image_patched = get_patched_image(image)
            
            if image != image_patched:
                patches.append({
                    "op": "replace",
                    "path": f"/spec/containers/{i}/image",
                    "value": image_patched
                })
                patched_image = True


        # add / create image pull secrets
        if patched_image:
            if 'imagePullSecrets' in pod_spec['spec']:
                patches.append({
                    "op": "add",
                    "path": "/spec/imagePullSecrets/-",
                    "value": {"name": os.getenv("HARBOR_MIRROR_PULL_SECRET_NAME")}
                })
            else:
                patches.append({
                    "op": "add",
                    "path": "/spec/imagePullSecrets",
                    "value": [{"name": os.getenv("HARBOR_MIRROR_PULL_SECRET_NAME")}]
                })

        if patches:
            response= {
                "apiVersion": "admission.k8s.io/v1",
                "kind": "AdmissionReview",
                "response": {
                    "uid": uid,
                    "allowed": True,
                    "patchType": "JSONPatch",
                    "patch": base64.b64encode(json.dumps(patches).encode('utf-8')).decode('utf-8')
                }
            }

            return jsonify(response)
    
    # fallback
    response = {
        "apiVersion": "admission.k8s.io/v1",
        "kind": "AdmissionReview",
        "response": {
            "uid": uid,
            "allowed": True  # Allow the request without modifications
        }
    }

    return jsonify(response)


@app.route('/ingress-dns', methods=['POST'])
def ingress_dns():
 
    admission_review = request.get_json()

    uid = admission_review['request']['uid']

    if os.getenv("BIND_DNS_UPDATE_KEY") and os.getenv("BIND_MASTER_IP") and os.getenv("INTERNAL_PROXY_FIP"):

        pprint.pprint(admission_review)
        
        # get all zones that our cloud bind is authoratative for
        bind_domains = funcs.get_bind_domains()

        ext_domains = funcs.get_ext_domains() # might be none
        
        if admission_review['request']['operation'] in ["CREATE", "UPDATE"]:
            # iterate ingress hosts and make dns updates for zones bind is authoratative for
            for rule in admission_review['request']['object']['spec']['rules']:
                host = rule['host']

                errors = []
                
                errors.extend(funcs.set_ingress_dyn_dns(bind_domains, host))
                errors.extend(funcs.set_ingress_ext_dyn_dns(ext_domains, host))
                
                if errors:
                    response = {
                            "apiVersion": "admission.k8s.io/v1",
                            "kind": "AdmissionReview",
                            "response": {
                                "uid": uid,
                                "allowed": False, # dont allow ingress submit since ingress dns failed
                                "status": {
                                    "status": "Failure",
                                    "message": ", ".join(errors),
                                    "reason": "InternalError",
                                    "code": 500
                                }
                            }
                        }

                    return jsonify(response)
        else:
            print(f"Operation {admission_review['request']['operation']} not implemented!")
            # todo: implement delete with oldObject, normal object is None on delete operation

    response = {
        "apiVersion": "admission.k8s.io/v1",
        "kind": "AdmissionReview",
        "response": {
            "uid": uid,
            "allowed": True  # Allow the request without modifications
        }
    }

    return jsonify(response)


def main():
    # todo: change to gunicorn / multi threaded
    app.run(host='0.0.0.0', port=443, ssl_context=(
        '/etc/tls/tls.crt',  # Path to TLS certificate
        '/etc/tls/tls.key'   # Path to TLS private key
    ))
