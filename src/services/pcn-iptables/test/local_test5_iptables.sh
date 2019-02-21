
source "${BASH_SOURCE%/*}/helpers.bash"

#test forwarding chain between namespaces
#Just test traffic correctly processed by the chain

function iptablescleanup {
    set +e
    bpf-iptables-clean
    sudo ip netns del ns1
    sudo ip link del veth1
    sudo ip netns del ns2
    sudo ip link del veth2
}
trap iptablescleanup EXIT

echo -e "\nTest $0 \n"
set -e
set -x

launch_iptables

enable_ip_forwarding

#create ns
for i in `seq 1 2`;
do
    sudo ip netns add ns${i}
    sudo ip link add veth${i}_ type veth peer name veth${i}
    sudo ip link set veth${i}_ netns ns${i}
    sudo ip netns exec ns${i} ip link set dev veth${i}_ up
    sudo ip link set dev veth${i} up

    sudo ifconfig veth${i} 10.0.${i}.254/24 up

    sudo ip netns exec ns${i} ifconfig veth${i}_ 10.0.${i}.1/24
    sudo ip netns exec ns${i} sudo ip route add default via 10.0.${i}.254

done

sudo ip netns exec ns1 ping 10.0.2.1 -c 2 -W 2

bpf-iptables -P INPUT DROP
bpf-iptables -P OUTPUT DROP

sudo ip netns exec ns1 ping 10.0.2.1 -c 2 -W 2

bpf-iptables -P FORWARD DROP

test_fail sudo ip netns exec ns1 ping 10.0.2.1 -c 2 -W 2

bpf-iptables -A FORWARD -d 10.0.2.1 -s 10.0.1.1 -j DROP

test_fail sudo ip netns exec ns1 ping 10.0.2.1 -c 2 -W 2
test_fail sudo ip netns exec ns2 ping 10.0.1.1 -c 2 -W 2

bpf-iptables -I FORWARD -s 10.0.2.1 -d 10.0.1.1 -j DROP

test_fail sudo ip netns exec ns1 ping 10.0.2.1 -c 2 -W 2
test_fail sudo ip netns exec ns2 ping 10.0.1.1 -c 2 -W 2

bpf-iptables -P INPUT ACCEPT
bpf-iptables -P OUTPUT ACCEPT

test_fail sudo ip netns exec ns1 ping 10.0.2.1 -c 2 -W 2
test_fail sudo ip netns exec ns2 ping 10.0.1.1 -c 2 -W 2

bpf-iptables -P INPUT DROP
bpf-iptables -P OUTPUT DROP

bpf-iptables -I FORWARD -s 10.0.2.1 -j ACCEPT
bpf-iptables -I FORWARD -s 10.0.1.1 -j ACCEPT

sudo ip netns exec ns1 ping 10.0.2.1 -c 2 -W 2
sudo ip netns exec ns2 ping 10.0.1.1 -c 2 -W 2

bpf-iptables -D FORWARD -s 10.0.2.1 -j ACCEPT
bpf-iptables -D FORWARD -s 10.0.1.1 -j ACCEPT

test_fail sudo ip netns exec ns1 ping 10.0.2.1 -c 2 -W 2
test_fail sudo ip netns exec ns2 ping 10.0.1.1 -c 2 -W 2

bpf-iptables -D FORWARD -d 10.0.2.1 -s 10.0.1.1 -j DROP
bpf-iptables -D FORWARD -s 10.0.2.1 -d 10.0.1.1 -j DROP

test_fail sudo ip netns exec ns1 ping 10.0.2.1 -c 2 -W 2
test_fail sudo ip netns exec ns2 ping 10.0.1.1 -c 2 -W 2

bpf-iptables -P FORWARD DROP

bpf-iptables -A FORWARD -p icmp -j ACCEPT

sudo ip netns exec ns1 ping 10.0.2.1 -c 2 -W 2
sudo ip netns exec ns2 ping 10.0.1.1 -c 2 -W 2
