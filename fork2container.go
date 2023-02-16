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
int sendMultipleFDs(
    char *sockPath,
    int chrootFD,
    int utsNamespaceFD,
    int pidNamespaceFD,
    int ipcNamespaceFD,
    int mntNamespaceFD)
{
    printf("send multiple fds\n");
    // Connect to server via socket.
    struct sockaddr_un_longer {
        // unsigned char sun_len;
        sa_family_t sun_family;
        char sun_path[512];
    };

    int s, len, ret;
    struct sockaddr_un_longer remote = {
        .sun_family = AF_UNIX
    };

    if ((s = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
        printf("error when open socket\n");
        return -1;
    }

    // remote.sun_family = AF_UNIX;
    strcpy(remote.sun_path, sockPath);
    len = strlen(remote.sun_path) + sizeof(remote.sun_family);
	printf("remote: %s\n", (char*)&remote);
    if (connect(s, (struct sockaddr *)&remote, len) == -1) {
        printf("errno is: %d\n", errno);
        printf("error when connect socket\n");
        return -1;
    }

    int fds[5];
    fds[0] = chrootFD;
    fds[1] = utsNamespaceFD;
    fds[2] = pidNamespaceFD;
    fds[3] = ipcNamespaceFD;
    fds[4] = mntNamespaceFD;

    if (sendfds(s, fds, 5) == -1) {
        printf("error when send fds\n");
        return -1;
    }

    char pid_arr[20];
    if (read(s, pid_arr, 20) < 0) {
        printf("error when recived pid\n");
        return -1;
    }

    int pid = atoi(pid_arr);

    if (close(s) == -1) {
        printf("error when close socket\n");
        return -1;
    }

    printf("send finished\n");
    return pid;
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
			Value: "fork.sock",
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
	getNamespacePath := func(namespace string) string {
		return "/proc/" +
			fmt.Sprint(targetContainerState.InitProcessPid) +
			"/ns/" +
			namespace
	}
	utsNamespace := getNamespacePath("uts")
	pidNamespace := getNamespacePath("pid")
	ipcNamespace := getNamespacePath("ipc")
	mntNamespace := getNamespacePath("mnt")

	utsNamespaceFd, err := os.Open(utsNamespace)
	if err != nil {
		return err
	}
	defer utsNamespaceFd.Close()
	pidNamespaceFd, err := os.Open(pidNamespace)
	if err != nil {
		return err
	}
	defer pidNamespaceFd.Close()
	ipcNamespaceFd, err := os.Open(ipcNamespace)
	if err != nil {
		return err
	}
	defer ipcNamespaceFd.Close()
	mntNamespaceFd, err := os.Open(mntNamespace)
	if err != nil {
		return err
	}
	defer mntNamespaceFd.Close()

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
	zygoteContainerRootfs := zygoteContainer.Config().Rootfs
	zygoteContainerForkSocketPath, err := securejoin.SecureJoin(zygoteContainerRootfs, forkSocketPath)
	fmt.Printf("socket path=%s\n", zygoteContainerForkSocketPath)
	if err != nil {
		return err
	}

	fmt.Println("get all fds")

	// send the fds to the socket
	pid, err := invokeMultipleFds(
		zygoteContainerForkSocketPath,
		targetContainerRootfsFd,
		utsNamespaceFd,
		pidNamespaceFd,
		ipcNamespaceFd,
		mntNamespaceFd,
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
	utsNamespaceFd *os.File,
	pidNamespaceFd *os.File,
	ipcNamespaceFd *os.File,
	mntNamespaceFd *os.File,
) (int, error) {
	cSock := C.CString(socketPath)
	defer C.free(unsafe.Pointer(cSock))

	pid, err := C.sendMultipleFDs(
		cSock,
		C.int(rootDir.Fd()),
		C.int(utsNamespaceFd.Fd()),
		C.int(pidNamespaceFd.Fd()),
		C.int(ipcNamespaceFd.Fd()),
		C.int(mntNamespaceFd.Fd()),
	)

	if err != nil {
		return -1, err
	}
	return int(pid), nil
}
