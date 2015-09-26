# ostree-docker-builder
Build a Docker image from an OStree commit.  ostree-docker-builder is
still a prototype.

# Usage

ostree-docker-builder --repo=$OSTREE_REPO --container-name=$DOCKER_IMAGE_NAME $OSTREE_COMMIT

# Example

This is the configuration file for creating a Docker container in
rpm-ostree:

emacs.json:
{
    "ref": "fedora-atomic/f22/x86_64/emacs",
    "repos": ["fedora-22"],
    "container": true,
    "packages": ["emacs"]
}


and have a fedora-22 repo file in the same directory:

fedora22.json:
[fedora-22]
name=Fedora 22 $basearch
mirrorlist=https://mirrors.fedoraproject.org/metalink?repo=fedora-22&arch=$basearch
enabled=0
gpgcheck=0
metadata_expire=1d


sudo rpm-ostree --repo=repo compose tree emacs.json

ostree-docker-builder --repo=repo -c emacs fedora-atomic/f22/x86_64/docker-host
