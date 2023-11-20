#!/usr/bin/env perl

# 
# 2023-11-12
# Maurice LAMBERT <mauricelambert434@gmail.com>
# https://github.com/mauricelambert/LinuxFirewall

###################
#    This file implements a CLI for firewall rules using iptables
#    Copyright (C) 2023  Maurice Lambert

#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.

#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.

#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <https://www.gnu.org/licenses/>.
###################

package LinuxFirewall;

use open qw( :encoding(UTF-8) :std );

our $NAME            = "LinuxFirewall";
our $VERSION         = "0.0.1";
our $AUTHOR          = "Maurice Lambert";
our $MAINTAINER      = "Maurice Lambert";
our $AUTHOR_MAIL     = 'mauricelambert434@gmail.com';
our $MAINTAINER_MAIL = 'mauricelambert434@gmail.com';

our $DESCRIPTION = "This file implements a CLI for firewall rules using iptables.";
our $URL         = "https://github.com/mauricelambert/$NAME";
our $LICENSE     = "GPL-3.0 License";
our $COPYRIGHT   = <<'EOF';
LinuxFirewall  Copyright (C) 2023  Maurice Lambert
This program comes with ABSOLUTELY NO WARRANTY.
This is free software, and you are welcome to redistribute it
under certain conditions.
EOF

print $COPYRIGHT;

use Getopt::Long;

# sudo perl LinuxFirewall.pl --dont_write_log --reject_as_default_block_policy --reject_as_portscan_block_policy --trusted_network --udp_input_ports=53,67,68 --tcp_input_ports=80,443,22 --udp_output_ports=53,67 --tcp_output_ports=80,443,22,21,445 --tcp_bruteforce_protect_ports=22,21 --time_portscan_rule=30 --hits_portscan_rule=25 --time_bruteforce_rule=666666 --hits_bruteforce_rule=50 --time_synflood_rule=25 --hits_synflood_rule=35 --icmp_block --icmp_limit=2 --dont_icmp_request_only --ipv4_whitelist=10.0.0.0/8,172.16.0.0/12 --ipv4_blacklist=192.168.0.0/16 --ipv6_blacklist=ff00::1,ff00::2  --ipv6_whitelist=fe80::/64 --ports_redirect=80:8000,443:4443 --dont_block_intranet --dont_disable_ipv6 --dont_print_output

# Tables:
#     Filter: INPUT, OUTPUT, FORWARD
#     NAT: PREROUTING, POSTROUTING, OUTPUT
#     Mangle: PREROUTING, POSTROUTING, INPUT, OUTPUT, FORWARD
#     Raw: PREROUTING, OUTPUT

my $write_log = 1;
my $print_output = 1;
my $block_policy_base = 'DROP'; # or REJECT
my $block_policy_portscan = 'DROP'; # or REJECT
# DROP is better against DDOS attack and for discretion when hacker don't know this IP is used (no response: no host or firewall filtering)
# REJECT is better for protection when hacker know this IP is used (RFC response and default OS response: host is used but port is closed - don't detect firewall and packets filtering)

my @udp_untrusted_open_ports = ( 53, 67, 68 );
# my @udp_untrusted_open_ports = ( 53, 68 );
my @tcp_untrusted_open_ports = ( );
# my @tcp_untrusted_open_ports = ( 8001 );
my @tcp_output_untrusted_ports = ( 22, 443, 465, 587, 993, 995 ); # only common encryted flux are open (SSH, HTTP, SMTPS, POP3S, IMAPS)
# my @tcp_output_untrusted_ports = ( 21, 22, 25, 80, 443, 465, 587, 8000, 8001 );

my @udp_trusted_open_ports = ( 53, 67, 68, 123, 135, 137, 138, 161, 162, 389, 464, 853, 1900, 5353, 5355 );
my @tcp_trusted_open_ports = ( 21, 22, 23, 25, 53, 80, 88, 110, 135, 139, 143, 443, 445, 464, 465, 514, 530, 587, 636, 853, 989, 990, 993, 995, 1080, 1433, 1434, 1521, 1526, 1723, 3000, 3306, 3307, 3268, 3269, 3389, 5000, 5433, 5434, 6514, 7474, 8000, 8080, 8888, 27017, 27018, 27019 );

my @input_udp_open_ports = @udp_untrusted_open_ports;
my @input_tcp_open_ports = @tcp_untrusted_open_ports;

my @output_udp_open_ports = @udp_untrusted_open_ports;
my @output_tcp_open_ports = @tcp_output_untrusted_ports;

my @tcp_bruteforce_protection_ports = ( 21, 22, 23, 25, 110, 143, 465, 530, 587, 993, 995 );

my $portscan_rule_time = 20;
my $portscan_hits = 5;

my $bruteforce_rule_time = 86400;
my $bruteforce_hits = 150;

my $synflood_rule_time = 30;
my $synflood_hits = 80;

my $icmp_limit = '1';
my $icmp_block = 1;
my $icmp_block_listen_and_response_only = 1;

my @whitelist_v4 = (  );
# my @whitelist_v4 = ( '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '1.1.1.1', '4.4.4.4', '8.8.8.8' );
my @whitelist_v6 = (  );
# my @whitelist_v6 = ( 'fe80::/10' );

my @blacklist_v4 = (  );
my @blacklist_v6 = (  );

my %ports_redirect_to_localhost = ();
# my %ports_redirect_to_localhost = ( '8000' => '8001' );
# my %ports_redirect_to_localhost = ( '8000' => '8001', '8000' => '8001', '8000' => '8001', '8000' => '8001' );
# On trusted network you can redirect port from local network incomming packets to localhost, it's is useful against port scan,
# on localhost your application run on port 8000 and the application can be used from local network with not common and unknown port 8001

$block_arp_spoofing = 1;
$block_local_network_except_gateway = 1;
$disable_ipv6 = 1;

#############
# Configuration with command line
#############

my $dont_write_log = '';
my $dont_print_output = '';
my $reject_as_default_block_policy = '';
my $reject_as_portscan_block_policy = '';
my @udp_input_ports = (  );
my @tcp_input_ports = (  );
my @udp_output_ports = (  );
my @tcp_output_ports = (  );
my @tcp_bruteforce_protect_ports = (  );
my $dont_icmp_request_only = '';
my $trusted_network = '';
my $dont_block_intranet = '';
my $dont_block_mim = '';
my $dont_disable_ipv6 = '';

GetOptions(
    "dont_write_log" => \$dont_write_log,
    "dont_print_output" => \$dont_print_output,
    "reject_as_default_block_policy" => \$reject_as_default_block_policy,
    "reject_as_portscan_block_policy" => \$reject_as_portscan_block_policy,
    "trusted_network" => \$trusted_network,
    "udp_input_ports=s" => \@udp_input_ports,
    "tcp_input_ports=s" => \@tcp_input_ports,
    "udp_output_ports=s" => \@udp_output_ports,
    "tcp_output_ports=s" => \@tcp_output_ports,
    "tcp_bruteforce_protect_ports=s" => \@tcp_bruteforce_protect_ports,
    "time_portscan_rule=s" => \$portscan_rule_time,
    "hits_portscan_rule=s" => \$portscan_hits,
    "time_bruteforce_rule=s" => \$bruteforce_rule_time,
    "hits_bruteforce_rule=s" => \$bruteforce_hits,
    "time_synflood_rule=s" => \$synflood_rule_time,
    "hits_synflood_rule=s" => \$synflood_hits,
    "icmp_block" => \$icmp_block,
    "icmp_limit=s" => \$icmp_limit,
    "dont_icmp_request_only" => \$dont_icmp_request_only,
    "ipv4_whitelist=s" => \@whitelist_v4,
    "ipv6_whitelist=s" => \@whitelist_v6,
    "ipv4_blacklist=s" => \@blacklist_v4,
    "ipv6_blacklist=s" => \@blacklist_v6,
    "ports_redirect=s" => \@ports_redirect,
    "dont_block_intranet" => \$dont_block_intranet,
    "dont_disable_ipv6" => \$dont_disable_ipv6
);

sub digits_arguments {
    foreach $_ ( @_ ) {
        m/^\d+$/ or die "${_} is not a digit (found in command line arguments)";
    }
    return @_;
}

sub ports_in_ports_list {
    my ( $ports, $other_ports ) = @_;
    foreach my $port ( @{$ports} ) {
        my $check = 0;
        foreach my $other_port ( @{$other_ports} ) {
            if ($port == $other_port) {
                $check = 1;
            }
        }

        if ( not $check ) {
            print("\x{1b}[34m [-] ${port} in bruteforce protection is not in TCP inputs open ports\x{1b}[0m\n");
        }
    }
}

sub get_ports_redirect {
    my %ports_redirect = (  );
    foreach $_ ( @_ ) {
        m/^\d+:\d+$/ or die "${_} is not valid, ports redirect format";
        my ( $port1, $port2 ) = split(/,/, $_);
        $ports_redirect{$port1} = $port2;
    }
    return \%ports_redirect;
}

@udp_input_ports = digits_arguments(split(/,/, join(',', @udp_input_ports)));
@tcp_input_ports = digits_arguments(split(/,/, join(',', @tcp_input_ports)));
@udp_output_ports = digits_arguments(split(/,/, join(',', @udp_output_ports)));
@tcp_output_ports = digits_arguments(split(/,/, join(',', @tcp_output_ports)));
@tcp_bruteforce_protect_ports = digits_arguments(split(/,/, join(',', @tcp_bruteforce_protect_ports)));

@whitelist_v4 = split(/,/, join(',', @whitelist_v4));
@whitelist_v6 = split(/,/, join(',', @whitelist_v6));

@blacklist_v4 = split(/,/, join(',', @blacklist_v4));
@blacklist_v6 = split(/,/, join(',', @blacklist_v6));

$ports_redirect = split(/,/, join(',', @ports_redirect));

ports_in_ports_list(\@tcp_bruteforce_protect_ports, \@tcp_input_ports);

$write_log = $dont_write_log eq '' ? $write_log : not $dont_write_log;
$print_output = $dont_print_output eq '' ? $print_output : not $dont_print_output;

$block_policy_base = $reject_as_default_block_policy ? 'REJECT' : 'DROP';
$block_policy_portscan = $reject_as_portscan_block_policy ? 'REJECT' : 'DROP';

@input_udp_open_ports = $trusted_network ? @udp_trusted_open_ports : @udp_untrusted_open_ports;
@input_tcp_open_ports = $trusted_network ? @tcp_trusted_open_ports : @tcp_untrusted_open_ports;
@output_udp_open_ports = $trusted_network ? @udp_trusted_open_ports : @udp_untrusted_open_ports;
@output_tcp_open_ports = $trusted_network ? @tcp_trusted_open_ports : @tcp_output_untrusted_ports;

@input_udp_open_ports = scalar(@udp_input_ports) ? @udp_input_ports : @input_udp_open_ports;
@input_tcp_open_ports = scalar(@tcp_input_ports) ? @tcp_input_ports : @input_tcp_open_ports;
@output_udp_open_ports = scalar(@udp_output_ports) ? @udp_output_ports : @output_udp_open_ports;
@output_tcp_open_ports = scalar(@tcp_output_ports) ? @tcp_output_ports : @output_tcp_open_ports;

@tcp_bruteforce_protection_ports = scalar(@tcp_bruteforce_protect_ports) ? @tcp_bruteforce_protect_ports : @tcp_bruteforce_protection_ports;

digits_arguments($portscan_rule_time, $portscan_hits, $bruteforce_rule_time, $bruteforce_hits, $synflood_rule_time, $synflood_hits, $icmp_limit);

$icmp_block_listen_and_response_only = $dont_icmp_request_only eq '' ? $icmp_block_listen_and_response_only : not $dont_icmp_request_only;

%ports_redirect_to_localhost = %{$ports_redirect};

$block_arp_spoofing = $dont_block_mim eq '' ? $block_arp_spoofing : not $dont_block_mim;
$block_local_network_except_gateway = $dont_block_intranet eq '' ? $block_local_network_except_gateway : not $dont_block_intranet;
$disable_ipv6 = $dont_disable_ipv6 eq '' ? $disable_ipv6 : not $dont_disable_ipv6;

#####
# Do not change following values (it's SYSLOG constants)
#####

my $LOG_EMERG = '0';
my $LOG_ALERT = '1';
my $LOG_CRIT = '2';
my $LOG_ERR = '3';
my $LOG_WARNING = '4';
my $LOG_NOTICE = '5';
my $LOG_INFO = '6';
my $LOG_DEBUG = '7';

sub mac_to_ipv6_link_local {
    my $mac = shift;
    my $eui64 = $mac;
    $eui64 =~ s/://g;
    substr($eui64, 6, 0, "ff");
    substr($eui64, 8, 0, "fe");
    my $ipv6 = "fe80::" . sprintf("%02x", hex(substr($eui64, 0, 2)) ^ 2) . substr($eui64, 2, 2) . ":" . substr($eui64, 4, 4) . ":" . substr($eui64, 8, 4) . ":" . substr($eui64, 12, 4);
    return $ipv6;
}

sub list_rules {
    my ( $executable ) = @_;
    if ($print_output) {
        system { $executable } ( $executable, '-L' );
    }
}

sub log_rule {
    # --log-level, --log-prefix, --log-uid
    if ($write_log) {
        system { @_[0] } @_;
    }
}

sub print_console {
    my ( $message, $color, $character ) = @_;
    if ($print_output) {
        print ("\x{1b}[${color}m [${character}] ${message}\x{1b}[0m\n");
    }
}

sub print_ok {
    my ( $message ) = @_;
    print_console($message, '32', '+');
}

sub print_info {
    my ( $message ) = @_;
    print_console($message, '34', '*');
}

sub print_nok {
    my ( $message ) = @_;
    print_console($message, '33', '-');
}

sub print_error {
    my ( $message ) = @_;
    print_console($message, '31', '!');
}

sub get_ports {
    my ( @ports ) = @_;
    my @port_strings = ( );
    my $port_length = scalar(@ports);
    
    for (my $index = 0; $index < $port_length; $index += 15) {
        my $higher_index = $index + 14; 
        if ($higher_index < $port_length) {
            push(@port_strings, join(',', @ports[ $index..$higher_index ]));
        } else {
            push(@port_strings, join(',', @ports[ $index..$port_length - 1 ]));
        }
    }

    return @port_strings;
}

print_info('Reset and set the secure policy on filter table chains');

my @executables = ( '/sbin/iptables', '/sbin/ip6tables', '/sbin/arptables' );
my @policies = ( 'ACCEPT', 'DROP' ); # REJECT is not valid for default policies INPUT, FORWARD and OUTPUT

foreach my $executable ( @executables ) {
    list_rules($executable);
    print_ok ("${executable} list");
}

@executables = ( '/sbin/iptables', '/sbin/ip6tables' );
foreach my $policy ( @policies ) {
    foreach my $executable ( @executables ) {
        system { $executable } ( $executable, '-F' );
        print_ok ("${executable} flush");

        my @chains = ( 'INPUT', 'OUTPUT', 'FORWARD' );

        foreach my $chain ( @chains ) {
            print_info ("${executable} define ${policy} for ${chain}\n");
            system { $executable } ( $executable, '-P', $chain,  $policy );
        }
    }
}

print_ok('Policies for filtering chains are secure.');
print_info('Create new chains for filtering and optimization');

my @base_rules = ( 'INPUT', 'OUTPUT' );
my @protocols_ports = ( 'TCP', 'UDP' );
my @protocols = ( 'ICMP', 'TCP', 'UDP' );
my @chains = ( 'INPUT_PROTO', 'OUTPUT_PROTO', 'BRUTEFORCE' );

foreach my $base_rule ( @base_rules ) {
    foreach my $protocol ( @protocols ) {
        push(@chains, "${base_rule}_${protocol}");
    }

    foreach my $protocol ( @protocols_ports ) {
        push(@chains, "${base_rule}_${protocol}_PORTS");
    }
}

foreach my $executable ( @executables ) {
    foreach my $chain ( @chains ) {
        system { $executable } ( $executable, '-N', $chain );
    }
}

print_ok('New chains for filtering and optimization are made.');
print_info('Block bruteforce attacks');

foreach my $executable ( @executables ) {
    my @ports = get_ports(@tcp_bruteforce_protection_ports);
    for my $ports_ (@ports) {
        system { $executable } ( $executable, '-I', 'BRUTEFORCE', '-p', 'tcp', '-m', 'multiport', '--dport', $ports_, '-m', 'state', '--state', 'NEW', '-m', 'recent', '--set', '--name', 'bruteforce' );
        log_rule ( $executable, '-I', 'BRUTEFORCE', '-p', 'tcp', '-m', 'multiport', '--dport', $ports_, '-m', 'state', '--state', 'NEW', '-m', 'recent', '--update', '--name', 'bruteforce', '--seconds', $bruteforce_rule_time, '--hitcount', $bruteforce_hits, '-j', 'LOG', '--log-level', $LOG_CRIT, '--log-prefix', 'Bruteforce attack blocked' );
        system { $executable } ( $executable, '-I', 'BRUTEFORCE', '-p', 'tcp', '-m', 'multiport', '--dport', $ports_, '-m', 'state', '--state', 'NEW', '-m', 'recent', '--rcheck', '--name', 'bruteforce', '--seconds', $bruteforce_rule_time, '--hitcount', $bruteforce_hits, '-j', $block_policy_base );
    }
}

print_ok('Protected againsts bruteforce attacks.');
print_info('Accept new TCP connections on allowed ports and block SYN flood attacks');

foreach my $executable ( @executables ) {
    system { $executable } ( $executable, '-I', 'INPUT_TCP_PORTS', '-m', 'state', '--state', 'NEW', '-m', 'recent', '--set', '--name', 'synflood' );
    log_rule ($executable, '-I', 'INPUT_TCP_PORTS', '-m', 'state', '--state', 'NEW', '-m', 'recent', '--update', '--name', 'synflood', '--seconds', $synflood_rule_time, '--hitcount', $synflood_hits, '-j', 'LOG', '--log-level', $LOG_CRIT, '--log-prefix', 'SYN flood attack blocked' );
    system { $executable } ( $executable, '-I', 'INPUT_TCP_PORTS', '-m', 'state', '--state', 'NEW', '-m', 'recent', '--name', 'synflood', '--rcheck', '--seconds', $synflood_rule_time, '--hitcount', $synflood_hits, '-j', $block_policy_base );

    my @ports = get_ports(@input_tcp_open_ports);
    for my $ports_ (@ports) {
        system { $executable } ( $executable, '-I', 'INPUT_TCP_PORTS', '-p', 'tcp', '-m', 'multiport', '--dport', $ports_, '--syn', '-m', 'conntrack', '--ctstate', 'NEW', '-j', 'ACCEPT' );
    }
}

print_ok('Input TCP allowed ports are configured and SYN flood attacks blocked.');
print_info('Accept TCP established connections');

my @tcp_base_chains = ( 'OUTPUT_TCP', 'INPUT_TCP' );

foreach my $executable ( @executables ) {
    foreach my $chain ( @tcp_base_chains ) {
        system { $executable } ( $executable, '-I', $chain, '-m', 'conntrack', '--ctstate', 'ESTABLISHED', '-j', 'ACCEPT' );
    }
}

print_info('Block non SYN packets beginning connections');
print_info('Block too small or too large packets (invalid packets)');
print_info('Block port scan (count SYN valid packets on blocked ports and block on multiples matches)');

foreach my $executable ( @executables ) {
    log_rule ($executable, '-I', 'INPUT_TCP', '-p', 'tcp', '!', '--syn', '-m', 'conntrack', '--ctstate', 'NEW', '-j', 'LOG', '--log-level', $LOG_WARNING, '--log-prefix', 'New connection with non SYN packet' );
    system { $executable } ( $executable, '-I', 'INPUT_TCP', '-p', 'tcp', '!', '--syn', '-m', 'conntrack', '--ctstate', 'NEW', '-j', $block_policy_base );
    log_rule ($executable, '-I', 'INPUT_TCP', '-p', 'tcp', '-m', 'conntrack', '--ctstate', 'NEW', '-m', 'tcpmss', '!', '--mss', '536:65535', '-j', 'LOG', '--log-level', $LOG_WARNING, '--log-prefix', 'New connection with too small or too big packet' );
    system { $executable } ( $executable, '-I', 'INPUT_TCP', '-p', 'tcp', '-m', 'conntrack', '--ctstate', 'NEW', '-m', 'tcpmss', '!', '--mss', '536:65535', '-j', $block_policy_base );
    system { $executable } ( $executable, '-I', 'INPUT_TCP', '-p', 'tcp', '-j', 'INPUT_TCP_PORTS' );
    system { $executable } ( $executable, '-I', 'INPUT_TCP', '-m', 'state', '--state', 'NEW', '-m', 'recent', '--set', '--name', 'portscan' );
    log_rule ($executable, '-I', 'INPUT_TCP', '-m', 'state', '--state', 'NEW', '-m', 'recent', '--update', '--name', 'portscan', '--seconds', $portscan_rule_time, '--hitcount', $portscan_hits, '-j', 'LOG', '--log-level', $LOG_CRIT, '--log-prefix', 'TCP port scan blocked' );
    system { $executable } ( $executable, '-I', 'INPUT_TCP', '-m', 'state', '--state', 'NEW', '-m', 'recent', '--name', 'portscan', '--rcheck', '--seconds', $portscan_rule_time, '--hitcount', $portscan_hits, '-j', $block_policy_portscan );
    system { $executable } ( $executable, '-I', 'INPUT_TCP', '-j', 'BRUTEFORCE' );
}

print_ok('TCP inputs are configured.');
print_info('Accept new UDP connections on allowed ports');

foreach my $executable ( @executables ) {
    my @ports = get_ports(@input_udp_open_ports);
    for my $ports_ (@ports) {
        system { $executable } ( $executable, '-I', 'INPUT_UDP_PORTS', '-p', 'udp', '-m', 'multiport', '--sport', $ports_, '-j', 'ACCEPT' );
    }
}

print_ok('Input UDP allowed ports are configured.');
print_info('Block port scan (count UDP packets on blocked ports and block on multiples matches)');

foreach my $executable ( @executables ) {
    system { $executable } ( $executable, '-I', 'INPUT_UDP', '-p', 'udp', '-j', 'INPUT_UDP_PORTS' );
    system { $executable } ( $executable, '-I', 'INPUT_UDP', '-m', 'state', '--state', 'NEW', '-m', 'recent', '--set', '--name', 'UDPportscan' );
    log_rule ($executable, '-I', 'INPUT_UDP', '-m', 'state', '--state', 'NEW', '-m', 'recent', '--update', '--name', 'UDPportscan', '--seconds', $portscan_rule_time, '--hitcount', $portscan_hits, '-j', 'LOG', '--log-level', $LOG_CRIT, '--log-prefix', 'UDP port scan blocked' );
    system { $executable } ( $executable, '-I', 'INPUT_UDP', '-m', 'state', '--state', 'NEW', '-m', 'recent', '--rcheck', '--name', 'UDPportscan', '--seconds', $portscan_rule_time, '--hitcount', $portscan_hits, '-j', $block_policy_portscan );
}

print_ok('UDP inputs are configured.');
print_info('Block or limit ICMP connections');

if (not $icmp_block) {
    system { '/sbin/iptables' } ( '/sbin/iptables', '-I', 'INPUT_ICMP', '-p', 'icmp', '--icmp-type', 'echo-request', '-m', 'limit', '--limit', "${icmp_limit}/second", '-j', 'ACCEPT' );
    system { '/sbin/iptables' } ( '/sbin/iptables', '-I', 'INPUT_ICMP', '-p', 'icmp', '--icmp-type', '11', '-m', 'limit', '--limit', "${icmp_limit}/second", '-j', 'ACCEPT' );
    system { '/sbin/ip6tables' } ( '/sbin/ip6tables', '-I', 'INPUT_ICMP', '-p', 'icmpv6', '--icmpv6-type', 'echo-request', '-m', 'limit', '--limit', "${icmp_limit}/second", '-j', 'ACCEPT' );
    system { '/sbin/ip6tables' } ( '/sbin/ip6tables', '-I', 'INPUT_ICMP', '-p', 'icmpv6', '--icmpv6-type', '11', '-m', 'limit', '--limit', "${icmp_limit}/second", '-j', 'ACCEPT' );
}

if (not $icmp_block or $icmp_block_listen_and_response_only) {
    system { '/sbin/iptables' } ( '/sbin/iptables', '-I', 'INPUT_ICMP', '-p', 'icmp', '--icmp-type', 'echo-reply', '-j', 'ACCEPT' );
    system { '/sbin/ip6tables' } ( '/sbin/ip6tables', '-I', 'INPUT_ICMP', '-p', 'icmpv6', '--icmpv6-type', 'echo-reply', '-j', 'ACCEPT' );
}

print_ok('ICMP inputs are configured (except IPv6 neighbor-advertisement and neighbor-solicitation for MIM protection).');
print_info('Redirect packets by protocols in specific chains');

@protocols = ( "UDP", "TCP" );
foreach my $executable ( @executables ) {
    foreach my $protocol ( @protocols ) {
        system { $executable } ( $executable, '-I', 'INPUT_PROTO', '-p', lc($protocol), '-j', "INPUT_${protocol}" );
    }
}

system { '/sbin/iptables' } ( '/sbin/iptables', '-I', 'INPUT_PROTO', '-p', 'icmp', '-j', 'INPUT_ICMP' );
system { '/sbin/ip6tables' } ( '/sbin/ip6tables', '-I', 'INPUT_PROTO', '-p', 'icmpv6', '-j', 'INPUT_ICMP' );

print_ok('Input chains are configured.');
print_info('Configure ICMP output');

if (not $icmp_block) {
    system { '/sbin/iptables' } ( '/sbin/iptables', '-I', 'OUTPUT_ICMP', '-p', 'icmp', '--icmp-type', 'echo-reply', '-m', 'limit', '--limit', "${icmp_limit}/second", '-j', 'ACCEPT' );
    system { '/sbin/ip6tables' } ( '/sbin/ip6tables', '-I', 'OUTPUT_ICMP', '-p', 'icmpv6', '--icmpv6-type', 'echo-reply', '-m', 'limit', '--limit', "${icmp_limit}/second", '-j', 'ACCEPT' );
}

if (not $icmp_block or $icmp_block_listen_and_response_only) {
    system { '/sbin/iptables' } ( '/sbin/iptables', '-I', 'OUTPUT_ICMP', '-p', 'icmp', '--icmp-type', 'echo-request', '-j', 'ACCEPT' );
    system { '/sbin/ip6tables' } ( '/sbin/ip6tables', '-I', 'OUTPUT_ICMP', '-p', 'icmpv6', '--icmpv6-type', 'echo-request', '-j', 'ACCEPT' );
}

system { '/sbin/ip6tables' } ( '/sbin/ip6tables', '-I', 'OUTPUT_ICMP', '-p', 'ipv6-icmp', '--icmpv6-type', 'neighbor-advertisement', '-j', 'ACCEPT' );
system { '/sbin/ip6tables' } ( '/sbin/ip6tables', '-I', 'OUTPUT_ICMP', '-p', 'ipv6-icmp', '--icmpv6-type', 'neighbor-solicitation' , '-j', 'ACCEPT' );

print_ok('Output ICMP is configured.');
print_info('Configure TCP output ports');

foreach my $executable ( @executables ) {
    my @ports = get_ports(@output_tcp_open_ports);
    for my $ports_ (@ports) {
        system { $executable } ( $executable, '-I', 'OUTPUT_TCP_PORTS', '-p', 'tcp', '-m', 'multiport', '--dport', $ports_, '--syn', '-m', 'conntrack', '--ctstate', 'NEW', '-j', 'ACCEPT' );
    }
}

print_ok('Output TCP is configured.');
print_info('Redirect UDP packets to output TCP ports rules');

foreach my $executable ( @executables ) {
    system { $executable } ( $executable, '-I', 'OUTPUT_TCP', '-p', 'tcp', '-j', 'OUTPUT_TCP_PORTS' );
}

print_info('Accept output UDP connections on allowed ports');

foreach my $executable ( @executables ) {
    my @ports = get_ports(@output_udp_open_ports);
    for my $ports_ (@ports) {
        system { $executable } ( $executable, '-I', 'OUTPUT_UDP_PORTS', '-p', 'udp', '-m', 'multiport', '--sport', $ports_, '-j', 'ACCEPT' );
    }
    system { $executable } ( $executable, '-I', 'OUTPUT_UDP', '-p', 'udp', '-j', 'OUTPUT_UDP_PORTS' );
}

print_ok('Output UDP ports are allowed.');
print_info('Redirect output packets to output rules by protocols');

foreach my $executable ( @executables ) {
    foreach my $protocol ( @protocols ) {
        system { $executable } ( $executable, '-I', 'OUTPUT_PROTO', '-p', lc($protocol), '-j', "OUTPUT_${protocol}" );
    }
}

system { '/sbin/iptables' } ( '/sbin/iptables', '-I', 'OUTPUT_PROTO', '-p', 'icmp', '-j', 'OUTPUT_ICMP' );
system { '/sbin/ip6tables' } ( '/sbin/ip6tables', '-I', 'OUTPUT_PROTO', '-p', 'icmpv6', '-j', 'OUTPUT_ICMP' );

print_ok('Output chains and rules are configured.');
print_info('Accept all on localhost');

@chains = ( 'INPUT', 'OUTPUT' );
foreach my $executable ( @executables ) {
    foreach my $chain ( @chains ) {
        system { $executable } ( $executable, '-A', $chain, '-' . lc(substr($chain, 0, 1)), 'lo', '-j', 'ACCEPT' );
    }
}

print_ok('Localhost traffic accepted.');
print_info('Block invalid packets');

foreach my $executable ( @executables ) {
    system { $executable } ( $executable, '-t', 'mangle', '-A', 'PREROUTING', '-m', 'conntrack', '--ctstate', 'INVALID', '-j', 'LOG', '--log-level', $LOG_WARNING, '--log-prefix', 'Invalid packets blocked' );
    system { $executable } ( $executable, '-t', 'mangle', '-A', 'PREROUTING', '-m', 'conntrack', '--ctstate', 'INVALID', '-j', 'DROP' ); # Cannot use REJECT for PREROUTING
    foreach my $chain ( @chains ) {
        system { $executable } ( $executable, '-A', $chain, '-j', "${chain}_PROTO" );
    }
}

print_ok('Block and log invalid packets');
print_info('Whitelist IP addresses and networks');

my %chains_ = ( 'INPUT' => '-s', 'OUTPUT' => '-d' );
foreach my $whitelist ( @whitelist_v4 ) {
    foreach my $chain ( keys %chains_ ) {
        system { '/sbin/iptables' } ( '/sbin/iptables', '-I', $chain, $chains_{$chain}, $whitelist, '-j', 'ACCEPT' );
    }
}

foreach my $whitelist ( @whitelist_v6 ) {
    foreach my $chain ( keys %chains_ ) {
        system { '/sbin/ip6tables' } ( '/sbin/ip6tables', '-I', $chain, $chains_{$chain}, $whitelist, '-j', 'ACCEPT' );
    }
}

print_ok('Whitelist is configured');
print_info('Blacklist IP addresses and networks');

my %chains_ = ( 'INPUT' => '-s', 'OUTPUT' => '-d' );
foreach my $blacklist ( @blacklist_v4 ) {
    foreach my $chain ( keys %chains_ ) {
        system { '/sbin/iptables' } ( '/sbin/iptables', '-I', $chain, $chains_{$chain}, $blacklist, '-j', $block_policy_base );
    }
}

foreach my $blacklist ( @blacklist_v6 ) {
    foreach my $chain ( keys %chains_ ) {
        system { '/sbin/ip6tables' } ( '/sbin/ip6tables', '-I', $chain, $chains_{$chain}, $blacklist, '-j', $block_policy_base );
    }
}

print_ok('Blacklist is configured');
print_info('Redirect local networks to localhost with port forwarding');

my @private_networks = ( '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16' );
foreach my $private_network ( @private_networks ) {
    foreach my $port ( keys %ports_redirect_to_localhost ) {
        system { '/sbin/iptables' } ( '/sbin/iptables', '-t', 'nat', '-I', 'PREROUTING', '-p', 'tcp', '--dport', $ports_redirect_to_localhost{$port}, '-s', $private_network, '-j', 'DNAT', '--to', "127.0.0.1:${port}" );
    }
}

foreach my $port ( keys %ports_redirect_to_localhost ) {
    system { '/sbin/ip6tables' } ( '/sbin/ip6tables', '-t', 'nat', '-I', 'PREROUTING', '-p', 'tcp', '--dport', $ports_redirect_to_localhost{$port}, '-s', 'fe80::/10', '-j', 'DNAT', '--to', "[::1]:${port}" );
}

my $route_localhost_value = scalar(keys(%ports_redirect_to_localhost)) ? '1': '0';
system { '/sbin/sysctl' } ( '/sbin/sysctl', '-w', "net.ipv4.conf.all.route_localnet=${route_localhost_value}" );

print_ok('Port forwadding from local networks to localhost is configured');

if ($block_arp_spoofing) {
    print_info('Block ARP spoofing');

    my $gateway_address;
    open(FILE, '<', '/proc/self/net/route') or die $!;
    my @lines = <FILE>;
    close(FILE);
    foreach my $line ( @lines ) {
        my @splitted_line = split(" ", $line);
        if ($splitted_line[7] eq "00000000") {
            $gateway_address = $splitted_line[2];
        }
    }

    $gateway_address =~ s/[0-9A-Fa-f]{2}\K(?=.)/./sg;

    my @gateway_ip = reverse(split(/\./, $gateway_address));
    for my $index (0 .. $#gateway_ip) {
        $gateway_ip[$index] = hex($gateway_ip[$index])
    }
    $gateway_address = join(".", @gateway_ip);
    $gateway_ip = $gateway_address;

    print_info("Get gateway IP address: ${gateway_address}");
    gethostbyaddr($gateway_address, 2);

    open(FILE, '<', '/proc/self/net/arp') or die $!;
    @lines = <FILE>;
    close(FILE);

    foreach my $line ( @lines ) {
        my @splitted_line = split(" ", $line);
        if ($splitted_line[0] eq $gateway_address) {
            $gateway_address = $splitted_line[3];
        }
    }

    print_info("Get gateway MAC address: ${gateway_address}");

    if ($block_local_network_except_gateway) {
        system { '/sbin/arptables' } ( '/sbin/arptables', '-A', 'INPUT', '-j', 'DROP' );
        system { '/sbin/arptables' } ( '/sbin/arptables', '-I', 'INPUT', '--source-mac', $gateway_address, '-j', 'ACCEPT' );
        # Block all ARP (so all IPv4 communication) with other hosts than gateway
        system { '/sbin/ip6tables' } ( '/sbin/ip6tables', '-I', 'INPUT_ICMP', '-p', 'ipv6-icmp', '--icmpv6-type', 'neighbor-advertisement', '--mac-source', $gateway_address, '-j', 'ACCEPT' );
        system { '/sbin/ip6tables' } ( '/sbin/ip6tables', '-I', 'INPUT_ICMP', '-p', 'ipv6-icmp', '--icmpv6-type', 'neighbor-solicitation' , '--mac-source', $gateway_address, '-j', 'ACCEPT' );
        print_ok('Links from layer 3 to layer 2 (ARP and ICMPv6 neighbor-advertisement/neighbor-solicitation) are allowed for gateway only');
    } else {
        my $gateway_ipv6 = mac_to_ipv6_link_local($gateway_address);
        system { '/sbin/arptables' } ( '/sbin/arptables', '-I', 'INPUT', '-p', 'Reply', '!', '--source-mac', $gateway_address, '--source', $gateway_ip, '-j', 'DROP' );
        system { '/sbin/arptables' } ( '/sbin/arptables', '-I', 'INPUT', '--opcode', '2', '!', '--source-mac', $gateway_address, '--source-ip', $gateway_ip, '-j', 'DROP' );
        # Block all ARP spoofing for gateway address to block MIM (Man In the Middle attack)
        system { '/sbin/ip6tables' } ( '/sbin/ip6tables', '-I', 'INPUT_ICMP', '-p', 'ipv6-icmp', '--icmpv6-type', 'neighbor-advertisement', '!', '--mac-source', $gateway_address, '--source', $gateway_ipv6, '-j', $block_policy_base );
        system { '/sbin/ip6tables' } ( '/sbin/ip6tables', '-I', 'INPUT_ICMP', '-p', 'ipv6-icmp', '--icmpv6-type', 'neighbor-solicitation' , '!', '--mac-source', $gateway_address, '--source', $gateway_ipv6, '-j', $block_policy_base );
        system { '/sbin/ip6tables' } ( '/sbin/ip6tables', '-I', 'INPUT_ICMP', '-p', 'ipv6-icmp', '--icmpv6-type', 'neighbor-advertisement', '-j', 'ACCEPT' );
        system { '/sbin/ip6tables' } ( '/sbin/ip6tables', '-I', 'INPUT_ICMP', '-p', 'ipv6-icmp', '--icmpv6-type', 'neighbor-solicitation' , '-j', 'ACCEPT' );
        print_ok('ARP and neighbor spoofing blocked (based on the current gateway MAC address and IP/IPv6)');
    }

    print_ok('MIM attacks protections are configured');
}

print_info("Disable/enable IPv6");

if ($disable_ipv6) {
    system { '/sbin/sysctl' } ( '/sbin/sysctl', '-w', "net.ipv6.conf.default.disable_ipv6=1" );
    system { '/sbin/sysctl' } ( '/sbin/sysctl', '-w', "net.ipv6.conf.all.disable_ipv6=1" );
}

print_ok('Your firewall is fully configured, you are protected with your configuration !');

@executables = ( '/sbin/iptables', '/sbin/ip6tables', '/sbin/arptables' );
foreach my $executable ( @executables ) {
    list_rules($executable);
}