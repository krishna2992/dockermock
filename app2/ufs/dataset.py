from pathlib import Path
import os
import shutil
from ..wrappers import unmount

def get_dataset(dataset_name:str):
    ds = Path(dataset_name)
    if not ds.exists(dataset_name):
        return None
    return ds

def get_dataset_snapshot(ds, snapshot_name: str):
    for snapshot in ds.snapshots:
        if snapshot.snapshot_name == snapshot_name:
            return snapshot
    return None


def clone_dataset(dataset, snapshot_name: str, targer_dataset:str, mountpoint:str=None):
    ds = Path(targer_dataset)
    ds.mkdir(parents=True, exist_ok=True)
    os.chown(ds, 0, 0)


def delete_dataset(ds_path: str):
    ds = Path(ds_path)
    if not ds.exists():
        return -1, "Dataset doesn't exist"
    if ds.is_mount():
        print('Unmount dataset', str(ds))
        unmount(str(ds))
    
    try:
        shutil.rmtree(ds)
    except Exception as e:
        print('Failed to destroy dataset:', e)
        return -1, 'Failed to destroy dataset'
    return 0, None
    