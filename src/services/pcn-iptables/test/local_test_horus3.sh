
source "${BASH_SOURCE%/*}/helpers.bash"

#test double insertion/delete rules in horus

function iptablescleanup {
    set +e
    polycubectl iptables del pcn-iptables
}
trap iptablescleanup EXIT

echo -e "\nTest $0 \n"
set -e
set -x

launch_iptables

ping $ip -W 1 -c 2 -W 2

pcn-iptables -P INPUT ACCEPT
pcn-iptables -P OUTPUT ACCEPT

ping $ip -W 1 -c 2 -W 2

pcn-iptables -P INPUT DROP

test_fail ping $ip -W 1 -c 2 -W 2

pcn-iptables -P INPUT ACCEPT

polycubectl pcn-iptables set horus=ON

ping $ip -W 1 -c 2 -W 2

pcn-iptables -A INPUT -s $ip -j DROP
pcn-iptables -A INPUT -s 1.2.3.4 -j DROP

test_fail ping $ip -W 1 -c 2 -W 2

pcn-iptables -D INPUT -s $ip -j DROP
pcn-iptables -D INPUT -s 1.2.3.4 -j DROP

pcn-iptables -S INPUT
pcn-iptables -L INPUT

ping $ip -W 1 -c 2 -W 2

pcn-iptables -A INPUT -s $ip -p icmp -j DROP
pcn-iptables -A INPUT -s 1.2.3.4 -p tcp -j DROP

test_fail ping $ip -W 1 -c 2 -W 2

pcn-iptables -D INPUT -s $ip -p icmp -j DROP
pcn-iptables -D INPUT -s 1.2.3.4 -p tcp -j DROP

pcn-iptables -S INPUT
pcn-iptables -L INPUT

ping $ip -W 1 -c 2 -W 2