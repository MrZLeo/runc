//go:build linux
// +build linux

package main

/*
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#define _GNU_SOURCE
#include <poll.h>
#include <sys/syscall.h>

#ifndef __NR_pidfd_open
#define __NR_pidfd_open 434
#endif

static int
pidfd_open(pid_t pid, unsigned int flags)
{
    return syscall(__NR_pidfd_open, pid, flags);
}

int sendfds(int s, int *fds, int fdcount)
{
    char buf[1];
    struct iovec iov;
    struct msghdr header;
    struct cmsghdr *cmsg;
    int n;
    char cms[CMSG_SPACE(sizeof(int) * fdcount)];

    buf[0] = 0;
    iov.iov_base = buf;
    iov.iov_len = 1;

    memset(&header, 0, sizeof header);
    header.msg_iov = &iov;
    header.msg_iovlen = 1;
    header.msg_control = (caddr_t)cms;
    header.msg_controllen = CMSG_LEN(sizeof(int) * fdcount);

    cmsg = CMSG_FIRSTHDR(&header);
    cmsg->cmsg_len = CMSG_LEN(sizeof(int) * fdcount);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    memmove(CMSG_DATA(cmsg), fds, sizeof(int) * fdcount);

    if ((n = sendmsg(s, &header, 0)) != iov.iov_len) {
        return -1;
    }

    return 0;
}

// Send multiple FDs to the unix socket
int sendMultipleFDs(const char *sockPath,
                    const int chrootFD,
                    const pid_t pid)
{
    printf("get pidfd\n");
    int pidFD;
    if ((pidFD = pidfd_open(pid, 0)) == -1) {
        printf("pidfd open fail\n");
		return -1;
    }
    printf("send multiple fds\n");
    // Connect to server via socket.
    int s, len, ret;

    if ((s = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
        printf("error when open socket\n");
        return -1;
    }

    struct sockaddr_un remote = { .sun_family = AF_UNIX };
    strcpy(remote.sun_path, sockPath);

    printf("socket path: %s\n", remote.sun_path);

    len = strlen(remote.sun_path) + sizeof(remote.sun_family);

    printf("remote: %s\n", (char *)&remote);
    if (connect(s, (struct sockaddr *)&remote, len) == -1) {
        printf("errno is: %d\n", errno);
        printf("error when connect socket\n");
        return -1;
    }

    int fds[2];
    fds[0] = chrootFD;
    fds[1] = pidFD;

    if (sendfds(s, fds, 2) == -1) {
        printf("error when send fds\n");
        return -1;
    }

    char pid_arr[20];
    if (read(s, pid_arr, 20) < 0) {
        printf("error when recived pid\n");
        return -1;
    }

    int targetPid = atoi(pid_arr);

    if (close(s) == -1) {
        printf("error when close socket\n");
        return -1;
    }

    printf("send finished\n");
    return targetPid;
}
*/
import "C"

import (
	"errors"
	"fmt"
	"os"
	"unsafe"

	securejoin "github.com/cyphar/filepath-securejoin"
	"github.com/opencontainers/runc/libcontainer/utils"
	"github.com/urfave/cli"
)

var fork2ContainerCommand = cli.Command{
	Name:        "fork2container",
	Description: "fork a process and land it in target container",
	Usage:       "runc fork2container",
	ArgsUsage:   "TODO",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  "zygote",
			Usage: "the container ID of the zygote container",
			Value: "",
		},
		cli.StringFlag{
			Name:  "target",
			Usage: "the container ID of the target container",
			Value: "",
		},
		cli.StringFlag{
			Name:  "fork-socket",
			Usage: "the relative path to the fork socket in the zygote container according to the bundle path",
			Value: "f.sk",
		},
	},
	Action: func(context *cli.Context) error {
		zygoteContainerID := context.String("zygote")
		if zygoteContainerID == "" {
			return errors.New("zygote container not specified")
		}
		targetContainerID := context.String("target")
		if targetContainerID == "" {
			return errors.New("target container not specified")
		}
		forkSocketPath := context.String("fork-socket")
		if forkSocketPath == "" {
			return errors.New("fork socket not specified")
		}

		err := doFork(context, zygoteContainerID, targetContainerID, forkSocketPath)
		if err != nil {
			fmt.Printf("fork2container error: %s\n", err)
			return err
		}
		return nil
	},
}

func doFork(context *cli.Context, zygoteContainerID string, targetContainerID string, forkSocketPath string) error {
	utils.Timestamp("start fork")
	// start fork
	zygoteContainer, err := getContainerByID(context, zygoteContainerID)
	if err != nil {
		return err
	}
	targetContainer, err := getContainerByID(context, targetContainerID)
	if err != nil {
		return err
	}
	// get cgroup manager and then apply the rule to new process that zygote fork
	targetrCgroupManager := targetContainer.CGroupsManager()
	if targetrCgroupManager == nil {
		return errors.New("cgroups manager is nil")
	}

	targetContainerState, err := targetContainer.State()
	if err != nil {
		return err
	}
	if targetContainerState == nil {
		return errors.New("target container state is nil")
	}

	zygoteContainerState, err := zygoteContainer.State()
	if err != nil {
		return err
	}
	if zygoteContainerState == nil {
		return errors.New("zygote container state is nil")
	}

	// open reuqired namespace fds
	// FIXME: why don't copy net namespace?
	// getNamespacePath := func(namespace string) string {
	// 	return "/proc/" +
	// 		// fmt.Sprint(targetContainerState.InitProcessPid) +
	// 		"325456" +
	// 		"/ns/" +
	// 		namespace
	// }
	// utsNamespace := getNamespacePath("uts")
	// pidNamespace := getNamespacePath("pid")
	// ipcNamespace := getNamespacePath("ipc")
	// mntNamespace := getNamespacePath("mnt")
	// netNamespace := getNamespacePath("net")

	// utsNamespaceFd, err := os.Open(utsNamespace)
	// if err != nil {
	// 	return err
	// }
	// defer utsNamespaceFd.Close()
	// pidNamespaceFd, err := os.Open(pidNamespace)
	// if err != nil {
	// 	return err
	// }
	// defer pidNamespaceFd.Close()
	// ipcNamespaceFd, err := os.Open(ipcNamespace)
	// if err != nil {
	// 	return err
	// }
	// defer ipcNamespaceFd.Close()
	// mntNamespaceFd, err := os.Open(mntNamespace)
	// if err != nil {
	// 	return err
	// }
	// defer mntNamespaceFd.Close()
	// netNamespaceFd, err := os.Open(netNamespace)
	// if err != nil {
	// 	return err
	// }

	// open the rootfs of target container
	// targetContainerBundle, _ := utils.Annotations(targetContainerState.Config.Labels)
	// targetContainerRootfs, err := securejoin.SecureJoin(targetContainerBundle, "rootfs")
	// if err != nil {
	// 	return err
	// }
	targetContainerRootfs := targetContainer.Config().Rootfs
	targetContainerRootfsFd, err := os.Open(targetContainerRootfs)
	if err != nil {
		return err
	}
	defer targetContainerRootfsFd.Close()

	fmt.Printf("target rootfs=%s\n", targetContainerRootfs)

	// find the path to zygote container fork socket
	// zygoteContainerBundle, _ := utils.Annotations(zygoteContainerState.Config.Labels)
	// TODO: socket path should be a path points to the volume
	// zygoteContainerRootfs := zygoteContainer.Config().Rootfs
	zygoteContainerVolume, err := func() (string, error) {
		mounts := zygoteContainer.Config().Mounts
		for _, mount := range mounts {
			if mount.Destination == "/cfork/" {
				return mount.Source, nil
			}
		}
		return "", errors.New("cannot find socket path for container fork")
	}()
	if err != nil {
		return err
	}

	zygoteContainerForkSocketPath, err := securejoin.SecureJoin(zygoteContainerVolume, forkSocketPath)
	fmt.Printf("socket path=%s\n", zygoteContainerForkSocketPath)
	if err != nil {
		return err
	}

	fmt.Println("get all fds")

	// send the fds to the socket
	pid, err := invokeMultipleFds(
		zygoteContainerForkSocketPath,
		targetContainerRootfsFd,
		targetContainerState.InitProcessPid,
		// utsNamespaceFd,
		// pidNamespaceFd,
		// ipcNamespaceFd,
		// mntNamespaceFd,
		// netNamespaceFd,
	)
	if err != nil {
		return err
	}

	fmt.Println("send fds success")

	// apply target container's cgroup to new process
	err = (*targetrCgroupManager).Apply(pid)
	if err != nil {
		return err
	}

	fmt.Println("apply cgroup success")

	return nil
}

// send namespace fds to target socketPath, recevice pid of new process
func invokeMultipleFds(
	socketPath string,
	rootDir *os.File,
	pid int,
) (int, error) {
	cSockPath := C.CString(socketPath)
	defer C.free(unsafe.Pointer(cSockPath))

	target_pid, err := C.sendMultipleFDs(cSockPath, C.int(rootDir.Fd()), C.pid_t(pid))

	if err != nil {
		return -1, err
	}
	return int(target_pid), nil
}
