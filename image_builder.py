import os
import json
import shlex
import requests
import subprocess
import argparse
import shutil
from app2.helpers import mount_devfs, unmount_jail_defvs

class MiniImageBuilder:

    def __init__(self, rootfs="./image_root"):
        self.rootfs = os.path.abspath(rootfs)
        self.meta_file = os.path.join(self.rootfs, "image.json")

        self.image = {
            "env": {},
            "workingDir": "/",
            "cmd": None
        }

        os.makedirs(self.rootfs, exist_ok=True)

    # ---------------------------
    # Utility
    # ---------------------------

    def save_metadata(self):
        with open(self.meta_file, "w") as f:
            json.dump(self.image, f, indent=4)

    def abs_path(self, path):
        return os.path.join(self.rootfs, path.lstrip("/"))

    # ---------------------------
    # Dockerfile commands
    # ---------------------------

    def cmd_COPY(self, args):
        parts = shlex.split(args)

        if len(parts) < 2:
            raise ValueError("COPY requires at least one source and one destination")

        *srcs, dst = parts

        print(f"[COPY] {srcs} -> {dst}")

        # resolve destination relative to workingDir if needed
        if not dst.startswith("/"):
            dst = os.path.join(self.image["workingDir"], dst)

        dst_root = self.abs_path(dst)

        # if multiple sources, destination must be directory
        if len(srcs) > 1 and not dst.endswith("/"):
            raise ValueError("When copying multiple files, destination must be a directory")

        os.makedirs(dst_root, exist_ok=True)

        for src in srcs:

            if not os.path.exists(src):
                raise FileNotFoundError(f"Source not found: {src}")

            # determine final destination path
            if dst.endswith("/"):
                dst_path = os.path.join(dst_root, os.path.basename(src))
            else:
                dst_path = dst_root

            # copy directory
            if os.path.isdir(src):
                shutil.copytree(src, dst_path, dirs_exist_ok=True)

            # copy file
            else:
                os.makedirs(os.path.dirname(dst_path), exist_ok=True)
                shutil.copy2(src, dst_path)

    def cmd_FROM(self, base):
        print(f"[FROM] {base}")
        self.image = requests.get(f'http://localhost:5000/api/images/{base}').json()
        # ensure required keys exist
        self.image.setdefault("env", {})
        self.image.setdefault("workingDir", "/")
        self.image.setdefault("cmd", None)

    def cmd_ENV(self, args):
        print(f"[ENV] {args}")

        parts = shlex.split(args)
        for p in parts:
            key, value = p.split("=", 1)
            self.image["env"][key] = value

    def cmd_WORKDIR(self, path):
        print(f"[workingDir] {path}")

        self.image["workingDir"] = path
        os.makedirs(self.abs_path(path), exist_ok=True)

    

    def cmd_RUN(self, command):
        print(f"[RUN] {command}")

        workingDir = self.image.get("workingDir", "/")
        try:
            subprocess.run(
                [   
                    "chroot", self.rootfs, 
                    "/bin/sh", "-c", command
                ], 
                check=True, 
                stdout=None,
                stderr=None
            )

        finally:
            print('Command completed succesfully')
        

    def cmd_CMD(self, command):
        print(f"[CMD] {command}")
        self.image["command"] = shlex.split(command)

    # ---------------------------
    # Parser
    # ---------------------------

    def execute(self, step, instruction, args):
        print(f'Step {step}:', end=' ')
        
        handler = getattr(self, f"cmd_{instruction}", None)

        if handler:
            handler(args)
        else:
            print(f"Unsupported instruction: {instruction}")

        self.save_metadata()

    def _clean_cache(self):
        pass

    def parse_dockerfile(self, path):
        step = 0
        try:
            print('Mounting rootfs:', self.rootfs)
            mount_devfs(self.rootfs)
            with open(path) as f:
                for line in f:
                    
                    line = line.strip()

                    if not line or line.strip().startswith("#"):
                        continue

                    parts = line.split(maxsplit=1)

                    instr = parts[0].upper()
                    args = parts[1] if len(parts) > 1 else ""
                    step+=1
                    self.execute(step, instr, args)
        finally:
            print('Unmounting rootfs:', self.rootfs)
            unmount_jail_defvs(self.rootfs)


# ---------------------------
# Main
# ---------------------------

if __name__ == "__main__":

    parser = argparse.ArgumentParser(description="Mini Image Builder")

    parser.add_argument(
        "-t",
        "--tag",
        required=True,
        help="Image name with optional tag (example: myimage:latest)"
    )

    parser.add_argument(
        "path",
        nargs="?",
        default=".",
        help="Dockerfile path or build directory (default: .)"
    )

    parser.add_argument(
        "--rootfs",
        required=True,
        help="Path to root filesystem"
    )

    args = parser.parse_args()

    # parse image name/tag
    if ":" in args.tag:
        image_name, image_tag = args.tag.split(":", 1)
    else:
        image_name = args.tag
        image_tag = "latest"

    build_path = args.path

    # resolve Dockerfile path
    if os.path.isdir(build_path):
        dockerfile_path = os.path.join(build_path, "Dockerfile")
    else:
        dockerfile_path = build_path

    if not os.path.exists(dockerfile_path):
        raise FileNotFoundError(f"Dockerfile not found: {dockerfile_path}")

    print(f"Building image: {image_name}:{image_tag}")
    print(f"Dockerfile: {dockerfile_path}")

    builder = MiniImageBuilder(args.rootfs)
    print(args.rootfs)
    exit(0)
    
    builder.parse_dockerfile(dockerfile_path)

    builder.image["name"] = image_name
    builder.image["tag"] = image_tag

    builder.save_metadata()

    print("\nBuild finished")
    with open('result.json', 'w') as f:
        f.write(json.dumps(builder.image, indent=4))
    print("Image config:\n", json.dumps(builder.image, indent=4))