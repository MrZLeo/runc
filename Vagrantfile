# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure("2") do |config|
# Fedora box is used for testing cgroup v2 support
  config.vm.box = "fedora/32-cloud-base"
  config.vm.provider :virtualbox do |v|
    v.memory = 2048
    v.cpus = 2
  end
  config.vm.provider :libvirt do |v|
    v.memory = 2048
    v.cpus = 2
  end
  config.vm.provision "shell", inline: <<-SHELL
    cat << EOF | dnf -y shell
config exclude kernel,kernel-core
config install_weak_deps false
update
install iptables gcc make golang-go libseccomp-devel bats jq git-core criu
ts run
EOF
    dnf clean all

    # Add a user for rootless tests
    useradd -u2000 -m -d/home/rootless -s/bin/bash rootless

    # Allow root to execute `ssh rootless@localhost` in tests/rootless.sh
    ssh-keygen -t ecdsa -N "" -f /root/rootless.key
    mkdir -m 0700 -p /home/rootless/.ssh
    cat /root/rootless.key.pub >> /home/rootless/.ssh/authorized_keys
    chown -R rootless.rootless /home/rootless

    # Add busybox for libcontainer/integration tests
    . /vagrant/tests/integration/multi-arch.bash \
        && mkdir /busybox \
        && curl -fsSL $(get_busybox) | tar xfJC - /busybox

    # Delegate cgroup v2 controllers to rootless user via --systemd-cgroup
    mkdir -p /etc/systemd/system/user@.service.d
    cat > /etc/systemd/system/user@.service.d/delegate.conf << EOF
[Service]
# default: Delegate=pids memory
# NOTE: delegation of cpuset requires systemd >= 244 (Fedora >= 32, Ubuntu >= 20.04). cpuset is ignored on Fedora 31.
Delegate=cpu cpuset io memory pids
EOF
    systemctl daemon-reload
  SHELL
end
