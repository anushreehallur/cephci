from cli.utilities.windows_utils import setup_windows_clients

from smb_operations import (
    deploy_smb_service_imperative,
    smb_cifs_mount,
    smb_cleanup,
    smbclient_check_shares,
    win_mount,
    clients_cleanup
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

    # Get cephfs volume
    cephfs_vol = config.get("cephfs_volume", "cephfs")

    # Get smb subvloume group
    smb_subvol_group = config.get("smb_subvolume_group", "smb")

    # Get smb subvolume mode
    smb_subvolume_mode = config.get("smb_subvolume_mode", "0777")

    # Get smb cluster id
    smb_cluster_id = config.get("smb_cluster_id", "smb1")

    # Get auth_mode
    auth_mode = config.get("auth_mode", "user")

    # Get domain_realm
    domain_realm = config.get("domain_realm", None)

    # Get custom_dns
    custom_dns = config.get("custom_dns", None)

    # Get smb user name
    smb_user_name = config.get("smb_user_name", "user1")

    # Get smb user password
    smb_user_password = config.get("smb_user_password", "passwd")

    # Get snapshot
    snap = config.get("snapshot", "snap1")

    # Get smb path
    path = config.get("path", "/")

    # Get cifs mount point
    cifs_mount_point = config.get("cifs_mount_point", "/mnt/smb")

    # Get window mount point
    mount_point = config.get("mount_point", "Z:")

    # Get VSS operations to perform
    operations = config.get("operations")

    # Get installer node
    installer = ceph_cluster.get_nodes(role="installer")[0]

    # Get smb nodes
    smb_nodes = ceph_cluster.get_nodes("smb")

    # Get client node
    client = ceph_cluster.get_nodes(role="client")[0]

    # Get Windows client flag
    windows_client = config.get("windows_client", False)

    if "spec" in config:
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
                if "public_addrs" in spec:
                    public_addrs = [
                        public_addrs["address"].split("/")[0]
                        for public_addrs in spec["public_addrs"]
                    ]
                else:
                    public_addrs = None
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
    else:
        # Get smb subvloumes
        smb_subvols = config.get("smb_subvolumes", ["sv1", "sv2"])

        # Get smb shares
        smb_shares = config.get("smb_shares", ["share1", "share2"])


    # Create windows clients obj
    if windows_client:
        clients = []
        for client in setup_windows_clients(config.get("windows_clients")):
            clients.append(client)
    else:
        clients = ceph_cluster.get_nodes(role="client")

    try:
        # deploy smb services
        deploy_smb_service_imperative(
            installer,
            cephfs_vol,
            smb_subvol_group,
            smb_subvols,
            smb_subvolume_mode,
            smb_cluster_id,
            auth_mode,
            smb_user_name,
            smb_user_password,
            smb_shares,
            path,
            domain_realm,
            custom_dns,
        )

        # Check smb share using smbclient
        smbclient_check_shares(
            smb_nodes,
            client,
            smb_shares,
            smb_user_name,
            smb_user_password,
            auth_mode,
            domain_realm,
        )

        # Mount samba share
        if windows_client:
            win_mount(
                clients,
                mount_point,
                smb_nodes[0].ip_address,
                smb_shares[0],
                smb_user_name,
                smb_user_password,
                public_addrs,
            )
        else:
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

        for operation in operations:
            # Check .snap Directory
            if operation == "access_snap":
                cmd = f"cd {cifs_mount_point}/.snap"
                out = client.exec_command(sudo=True, cmd=cmd)
                if "No such file or directory" in out[0]:
                    raise OperationFailedError(".snap directory is not enabled")
                else:
                    out = client.exec_command(
                        sudo=True, cmd=f"cd {cifs_mount_point}/.snap && pwd"
                    )
                    log.info(".snap directory is accessible, the path : {}".format(out))

            # Verify snapshot creation
            elif operation == "create_snapshot":
                cmd = (
                    f"cd {cifs_mount_point} && ceph fs subvolume snapshot create {cephfs_vol} {smb_subvols[0]} {snap} "
                    f"{smb_subvol_group}"
                )
                out = client.exec_command(sudo=True, cmd=cmd)
                log.info("Created snapshot : {}".format(out))
                out = client.exec_command(
                    sudo=True, cmd=f"cd {cifs_mount_point}/.snap && ls -al"
                )
                log.info("Snapshot created in .snap folder: {}".format(out))

            # Verify list snapshots
            elif operation == "list_snapshot":
                if windows_client:
                    cmd = (
                        f"dir \\\\{public_addrs[0]}\\{smb_shares[0]}\\.snap"
                    )
                    out, _ = client.exec_command(cmd=cmd)
                    if snap not in out:
                        raise OperationFailedError("Snapshot not listed, in Previous Versions")
                    else:
                        log.info("Previous versions listed as snapshot: {}".format(out))

                else:
                    cmd = (
                        f"cd {cifs_mount_point} && ceph fs subvolume snapshot ls {cephfs_vol} {smb_subvols[0]} "
                        f"{smb_subvol_group}"
                    )
                    out, _ = client.exec_command(sudo=True, cmd=cmd)
                    if snap not in out:
                        raise OperationFailedError("Snapshot is not listed")
                    else:
                        log.info("Snapshots listed {}".format(out))

            # Create file with content on share
            elif operation == "create_file":
                if windows_client:
                    cmd = f"echo Hello! > {mount_point}\win_file.txt"
                    client.exec_command(
                        cmd=cmd,
                    )
                    cmd = f"type {mount_point}\win_file.txt"
                    win_file_output, _ = client.exec_command(
                        cmd=cmd,
                    )
                else:
                    cmd = f"""cd {cifs_mount_point} && cat << EOF >test.txt
                                Hello!
                                """
                    client.exec_command(sudo=True, cmd=cmd)
                    cmd = f"cd {cifs_mount_point} && cat test.txt"
                    file_output, _ = client.exec_command(sudo=True, cmd=cmd)

            # Update the file on share
            elif operation == "update_file":
                if windows_client:
                    cmd = f"echo It is updated >> {mount_point}\win_file.txt"
                    client.exec_command(
                        cmd=cmd,
                    )
                else:
                    cmd = f"""cd {cifs_mount_point} && cat << EOF >test.txt
                                Hello! This is updated
                                """
                    client.exec_command(sudo=True, cmd=cmd)

            # Verify content of snapshot file and the file before update is same
            elif operation == "verify_snapshot_content":
                if windows_client:
                    cmd = f"type {mount_point}\win_file.txt"
                    out, _ = client.exec_command(
                        cmd=cmd,
                    )
                    if out != file_output:
                        raise OperationFailedError(
                            f"VSS feature not working. File content before editing {file_output}, "
                            f"File content of snapshot {out}"
                        )
                else:
                    cmd = f"cd {cifs_mount_point}/.snap/*{snap}* && cat test.txt"
                    out, _ = client.exec_command(sudo=True, cmd=cmd)
                    if out != file_output:
                        raise OperationFailedError(
                            f"VSS feature not working. File content before editing {file_output}, "
                            f"File content of snapshot {out}"
                        )
            # Create file with content on share
            elif operation == "create_file_in_directory":
                if windows_client:
                    cmd = f"mkdir {mount_point}\\test"
                    client.exec_command(
                        cmd=cmd,
                    )
                    cmd = f"echo Hello! > {mount_point}\\test\win_file.txt"
                    client.exec_command(
                        cmd=cmd,
                    )
                    cmd = f"type {mount_point}\\test\\win_file.txt"
                    win_file_output, _ = client.exec_command(
                        cmd=cmd,
                    )
            # Update the file on share
            elif operation == "update_file_in_directory":
                if windows_client:
                    cmd = f"echo It is updated >> {mount_point}\\test\\win_file.txt"
                    client.exec_command(
                        cmd=cmd,
                    )

            elif operation == "restore_file":
                if windows_client:
                    # cmd = (f"for /f \"delims=\" %A in ('dir /b \"\\\\{public_addrs[0]}\\{smb_shares[0]}\\"
                    #        f".snap\\*{snap}*\"') do @set resultVar= %A")
                    cmd = f"dir /b \"\\\\{public_addrs[0]}\\{smb_shares[0]}\\.snap\\*{snap}*"
                    out, _ = client.exec_command(
                        cmd=cmd,
                    )
                    cmd = (
                        f'copy "\\\\{public_addrs[0]}\\{smb_shares[0]}\\.snap\\{out}\\win_file.txt" '
                        f'"\\\\{public_addrs[0]}\\{smb_shares[0]}\\win_file.txt" /Y'
                    )
                    out, _ = client.exec_command(
                        cmd=cmd,
                    )
                    if "1 file(s) copied" not in out:
                        raise OperationFailedError(f"File not restored: {out}")
                    else:
                        cmd = f"type {mount_point}\\win_file.txt"
                        file_out, _ = client.exec_command(
                            cmd=cmd,
                        )
                        log.info("File restored successfully {}"
                                 "{}".format(out, file_out))

            elif operation == "restore_directory":
                if windows_client:
                    cmd = f"dir /b \"\\\\{public_addrs[0]}\\{smb_shares[0]}\\.snap\\*{snap}*"
                    out, _ = client.exec_command(
                        cmd=cmd,
                    )
                    cmd = (
                        f'xcopy "\\\\{public_addrs[0]}\\{smb_shares[0]}\\.snap\\{out}\\test\\*" '
                        f'"\\\\{public_addrs[0]}\\{smb_shares[0]}\\test\\*" /E /I /Y'
                    )
                    out, _ = client.exec_command(
                        cmd=cmd,
                    )
                    if "File(s) copied" not in out:
                        raise OperationFailedError(f"Directory not restored: {out}")
                    else:
                        cmd = f"type {mount_point}\\test"
                        dir_output, _ = client.exec_command(
                            cmd=cmd,
                        )
                        log.info("File in Directory restored successfully {}"
                                 "{}".format(out, dir_output))
            elif operation == "restore_share":
                if windows_client:
                    cmd = f"dir /b \"\\\\{public_addrs[0]}\\{smb_shares[0]}\\.snap\\*{snap}*"
                    out, _ = client.exec_command(
                        cmd=cmd,
                    )
                    cmd = (
                        f'xcopy "\\\\{public_addrs[0]}\\{smb_shares[0]}\\.snap\\{out}\\*" '
                        f'"\\\\{public_addrs[0]}\\{smb_shares[0]}\\*" /E /I /Y'
                    )
                    out, _ = client.exec_command(
                        cmd=cmd,
                    )
                    if "File(s) copied" not in out:
                        raise OperationFailedError(f"File not restored: {out}")
                    else:
                        cmd = f"type {mount_point}"
                        file, _ = client.exec_command(
                            cmd=cmd,
                        )
                        log.info("Share restored successfully {}".format(out))

    except Exception as e:
        log.error(f"Failed to deploy samba with auth_mode {auth_mode} : {e}")
        return 1
    finally:
        clients_cleanup(
            clients,
            mount_point,
            smb_nodes[0].ip_address,
            smb_shares[0],
            smb_user_name,
            smb_user_password,
            windows_client,
        )
        smb_cleanup(installer, smb_shares, smb_cluster_id)
    return 0
