import libzfs
import traceback
zfs = libzfs.ZFS()


def get_dataset(dataset_name:str):
    try:
        ds = zfs.get_dataset(dataset_name)
        return ds
    except libzfs.ZFSException as e:
        traceback.print_exc()
    return None

def get_dataset_snapshot(ds: libzfs.ZFSDataset, snapshot_name: str):
    for snapshot in ds.snapshots:
        if snapshot.snapshot_name == snapshot_name:
            return snapshot
    return None


def clone_dataset(dataset: libzfs.ZFSDataset, snapshot_name: str, targer_dataset:str, mountpoint:str=None):
    snapshot = get_dataset_snapshot(dataset, snapshot_name)
    if not snapshot:
        return -1
    try:
        snapshot.clone(targer_dataset)
        if mountpoint:
            ds = get_dataset(targer_dataset)
            ds.update_properties({'mountpoint':{'value':mountpoint}})
        return 0
    except Exception as e:
        print(traceback.print_exc())
    return -1


    