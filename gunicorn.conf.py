import multiprocessing


def on_starting(server):
    server._mirror_manager = multiprocessing.Manager()
    server.mirror_cache_dict = server._mirror_manager.dict()
    server.mirror_cache_lock = server._mirror_manager.Lock()


def post_fork(server, worker):
    import pve_cloud_ctrl.adm as adm

    adm.mirror_cache_lock = server.mirror_cache_lock
    adm.mirror_cache_dict = server.mirror_cache_dict