import os
from ceph.ceph_admin import CephAdmin
from cli.exceptions import ConfigError
from utility.utils import generate_self_signed_certificate
from smb_operations import (
    smb_cifs_mount,
    smb_cleanup,
    smbclient_check_shares, deploy_smb_service_declarative,
)

from cli.exceptions import OperationFailedError
from utility.log import Log

log = Log(__name__)


def run(ceph_cluster, **kw):
    """Deploy samba with auth_mode 'user' using imperative style(CLI Commands)
    Args:
        **kw: Key/value pairs of configuration information to be used in the test
    """
    # Get config
    config = kw.get("config")

    # Get cephadm obj
    cephadm = CephAdmin(cluster=ceph_cluster, **config)

    # Check mandatory parameter file_type
    if not config.get("file_type"):
        raise ConfigError("Mandatory config 'file_type' not provided")

    # Get spec file type
    file_type = config.get("file_type")

    # Check mandatory parameter spec
    if not config.get("spec"):
        raise ConfigError("Mandatory config 'spec' not provided")

    # Get smb spec file mount path
    file_mount = config.get("file_mount", "/tmp")

    # Get smb subvolume mode
    smb_subvolume_mode = config.get("smb_subvolume_mode", "0777")

    # Get cifs mount point
    cifs_mount_point = config.get("cifs_mount_point", "/mnt/smb")

    # Get smb path
    path = config.get("path", "/")

    # Get smb spec
    smb_spec = config.get("spec")

    # Get smb service value from spec file
    smb_shares = []
    smb_subvols = []
    for spec in smb_spec:
        if spec["resource_type"] == "ceph.smb.cluster":
            smb_cluster_id = spec["cluster_id"]
            auth_mode = spec["auth_mode"]
            if "domain_settings" in spec:
                domain_realm = spec["domain_settings"]["realm"]
            else:
                domain_realm = None
        elif spec["resource_type"] == "ceph.smb.usersgroups":
            smb_user_name = spec["values"]["users"][0]["name"]
            smb_user_password = spec["values"]["users"][0]["password"]
        elif spec["resource_type"] == "ceph.smb.join.auth":
            smb_user_name = spec["auth"]["username"]
            smb_user_password = spec["auth"]["password"]
        elif spec["resource_type"] == "ceph.smb.share":
            cephfs_vol = spec["cephfs"]["volume"]
            smb_subvol_group = spec["cephfs"]["subvolumegroup"]
            smb_subvols.append(spec["cephfs"]["subvolume"])
            smb_shares.append(spec["share_id"])
        elif spec["resource_type"] == "ceph.smb.tls.credential":
            cert_tls_credential_id = spec["remote_control"]["cert"]["ref"]
            key_tls_credential_id = spec["remote_control"]["key"]["ref"]
            cacert_tls_credential_id = spec["remote_control"]["ca_cert"]["ref"]

    # Get gRPC operations to perform
    grpc_operation = config.get("grpc_operation")

    # Get installer node
    installer_node = ceph_cluster.get_nodes(role="installer")[0]

    # Get smb nodes
    smb_nodes = ceph_cluster.get_nodes("smb")

    # Get client node
    client = ceph_cluster.get_nodes(role="client")[0]

    # Generate self signed certificates crt, cacrt, key
    key, cert, ca, _ = generate_self_signed_certificate_for_smb_node(installer_node)

    grpc_spec_tld_credential_dict = {
        "resource_type": "ceph.smb.tls.credential",
        "tls_credential_id": cert_tls_credential_id,
        "credential_type": "cert",
        "value": "|\n" + cert.rstrip("\\n"),
        "resource_type": "ceph.smb.tls.credential",
        "tls_credential_id": key_tls_credential_id,
        "credential_type": "cert",
        "value": "|\n" + key.rstrip("\\n"),
        "resource_type": "ceph.smb.tls.credential",
        "tls_credential_id": cacert_tls_credential_id,
        "credential_type": "cacert",
        "value": "|\n" + ca.rstrip("\\n"),
    }
    log.info("smb_spec: ",smb_spec)
    smb_spec.update(grpc_spec_tld_credential_dict)


    try:
        # deploy smb services
        deploy_smb_service_declarative(
            installer_node,
            cephfs_vol,
            smb_subvol_group,
            smb_subvols,
            smb_cluster_id,
            smb_subvolume_mode,
            file_type,
            smb_spec,
            file_mount,
        )

        # Check smb share using smbclient
        smbclient_check_shares(
            smb_nodes,
            client,
            smb_shares,
            smb_user_name,
            smb_user_password,
            auth_mode,
            domain_realm
        )

        # Install grpcurl
        install_grpcurl(installer_node)

        # Clone samba in kubernetes repo
        clone_the_samba_in_kubernetes_repo(config, installer_node)

        # Mount smb share with cifs
        smb_cifs_mount(
            smb_nodes[0],
            client,
            smb_shares[0],
            smb_user_name,
            smb_user_password,
            auth_mode,
            domain_realm,
            cifs_mount_point,
        )

        if grpc_operation == "check_remotectl":
            check_remotectl_service(installer_node)




    except Exception as e:
        log.error(f"Failed to deploy samba with auth_mode {auth_mode} : {e}")
        return 1
    finally:
        client.exec_command(
            sudo=True,
            cmd=f"umount {cifs_mount_point}",
        )
        client.exec_command(
            sudo=True,
            cmd=f"rm -rf {cifs_mount_point}",
        )
        smb_cleanup(installer_node, smb_shares, smb_cluster_id)
    return 0

def check_remotectl_service(smb_node):
    """Check if grpc remotectl service is running
            Args:
                smb_nodes (list): samba server nodes obj list
                smb_cluster_id (str): samba cluster id
    """
    # Get samba service
    cmd = "systemctl list-units --type=service | grep remotectl"
    out = smb_node.exec_command(sudo=True, cmd=cmd)[0].strip()

    if "remotectl" in out:
        log.info(f"gRPC remotectl service has been loaded: {out}")
    else:
        raise OperationFailedError(f"gRPC remotectl service has not been loaded {out}")

    if "remotectl" in out & "active" in out & "running" in out:
        log.info(f"gRPC remotectl service is running activetly: {out}")
    else:
        raise OperationFailedError(f"gRPC remotectl service has been loaded but failed {out}")

def generate_self_signed_certificate_for_smb_node(installer_node):
    """Generate self signed certificates for samba node
            Args:
                installer_node (obj): samba server node installer node obj
    """
    subject = {
        "common_name": installer_node.hostname,
        "ip_address": installer_node.ip_address,
    }
    key, cert, ca = generate_self_signed_certificate(subject=subject)
    with open(f"{subject['common_name']}.key", "w") as f:
        f.write(key)
    with open(f"{subject['common_name']}.crt", "w") as f:
        f.write(cert)
    with open(f"{subject['common_name']}.ca", "w") as f:
        f.write(ca)
    abs_path = (
        os.path.abspath(f"{subject['common_name']}.key"),
        os.path.abspath(f"{subject['common_name']}.crt"),
        os.path.abspath(f"{subject['common_name']}.ca"))

    return key, cert, ca, abs_path

def install_grpcurl(smb_node):
    """Install grpcurl package"""
    log.info("install grpcurl package")
    wget_cmd = "curl -LO https://github.com/fullstorydev/grpcurl/releases/download/v1.8.9/grpcurl_1.8.9_linux_x86_64.tar.gzz"

    tar_cmd = "tar -xvzf grpcurl_1.8.9_linux_x86_64.tar.gz"
    chmod_cmd = "chmod +x grpcurl"
    rename_cmd = "sudo mv grpcurl /usr/local/bin/"
    version_cmd = "grpcurl --version"
    out, _ = smb_node.exec_command(
        cmd=wget_cmd,
        sudo=True,
    )
    log.info(out)
    smb_node.exec_command(
        cmd=f"{tar_cmd} && {chmod_cmd} && {rename_cmd}",
        sudo=True,
    )
    out, _ = smb_node.exec_command(
        cmd=version_cmd,
        sudo=True,
    )
    log.info(out)
    if "grpcurl" not in out:
        raise Exception(" grpcurl not installed")

def clone_the_samba_in_kubernetes_repo(config, node):
    """clone the repo on to the node.

    Args:
        config: test config
        node: ceph node
    """
    log.info("cloning the https://github.com/samba-in-kubernetes/sambacc.git repo")
    git_clone_cmd = f"git clone https://github.com/samba-in-kubernetes/sambacc.git"
    node.exec_command(cmd=git_clone_cmd, sudo=True)
