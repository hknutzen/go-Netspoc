package main

/*
Pass 2 of Netspoc - A Network Security Policy Compiler

(C) 2017 by Heinz Knutzen <heinz.knutzen@googlemail.com>

http://hknutzen.github.com/Netspoc

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License along
with this program; if not, write to the Free Software Foundation, Inc.,
51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

*/

import (
	"bufio"
	"bytes"
	"fmt"
	"github.com/mailru/easyjson"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

type Config struct {
	concurrent int
	pipe bool
}

var (
	zero_ip = net.ParseIP("0.0.0.0")
	max_ip  = net.ParseIP("255.255.255.255")
	show_diag = false
	config = Config{concurrent: 2, pipe: false}
)

func fatal_err (format string, args ...interface{}) {
	panic(fmt.Sprintf(format, args...))
}

func info (format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, format, args...)
}

func diag_msg (msg string) {
	if show_diag {
		fmt.Fprintln(os.Stderr, msg)
	}
}

type IP_Net struct {
	net *net.IPNet
	opt_networks, no_opt_addrs, need_protect bool
	name string
	up *IP_Net
	is_supernet_of_need_protect map[*IP_Net]bool
}
type Proto struct {
	proto string
	ports [2]int
	established bool
	type_, code int
	name string
	up *Proto
}
type Name2IP_Net map[string]*IP_Net

func create_ip_obj (ip_net string) (*IP_Net) {
	_, net, _ := net.ParseCIDR(ip_net)
	return &IP_Net{ net: net, name: ip_net }
}

func get_ip_obj (ip net.IP, mask net.IPMask, ip_net2obj Name2IP_Net) (*IP_Net) {
	name := ip.String() + "/" + mask.String()
	obj, ok := ip_net2obj[name];
	if !ok {
		obj = &IP_Net{ net: &net.IPNet{ IP: ip, Mask: mask }, name: name }
		ip_net2obj[name] = obj
	}
	return obj
}

func create_prt_obj (descr string) (Proto) {
	splice := strings.Split(descr, " ")
	proto, n1, n2, established := splice[0], splice[1], splice[2], splice[3]
	prt := Proto{ proto: proto, name: descr }
    
	if proto == "tcp" || proto == "udp" {
		p1, _ := strconv.Atoi(n1)
		p2, _ := strconv.Atoi(n2)
		prt.ports = [...]int{ p1, p2 }
		if established != "" {
			 prt.established = true
		}
	} else if proto == "icmp" {
		if n1 != "" {
			prt.type_, _ = strconv.Atoi(n1)
			if n2 != "" {
				prt.code, _ = strconv.Atoi(n2)
			} else {
				prt.code = -1
			}
		} else {
			prt.type_ = -1
		}
	}
	return prt
}

type ByMask []net.IPMask

func (s ByMask) Len() int {
    return len(s)
}
func (s ByMask) Swap(i, j int) {
    s[i], s[j] = s[j], s[i]
}
func (s ByMask) Less(i, j int) bool {
    return bytes.Compare(s[i], s[j]) < 0
}

func setup_ip_net_relation (ip_net2obj Name2IP_Net) {
	if _, ok := ip_net2obj["0.0.0.0/0"]; !ok {
		ip_net2obj["0.0.0.0/0"] = create_ip_obj("0.0.0.0/0")
	}
	mask_ip_hash := make(map[string]map[string]*IP_Net)

	// Collect networks into mask_ip_hash.
	for _, network := range ip_net2obj {
		ip, mask := network.net.IP, network.net.Mask
		ip_map, ok := mask_ip_hash[string(mask)]
		if !ok {
			ip_map := make(map[string]*IP_Net)
			mask_ip_hash[string(mask)] = ip_map
		}
		ip_map[string(ip)] = network
	}

	// Compare networks.
	// Go from smaller to larger networks.
	var mask_list []net.IPMask
	for k := range mask_ip_hash { mask_list = append(mask_list, net.IPMask(k)) }
	sort.Sort(sort.Reverse(ByMask(mask_list)))
	for i, mask := range mask_list {
		upper_masks := mask_list[i+1:]

		// No supernets available
		if len(upper_masks) == 0 { break }
        
		ip_hash := mask_ip_hash[string(mask)]
		for ip, subnet := range ip_hash {
            
			// Find networks which include current subnet.
			// upper_masks holds masks of potential supernets.
			for _, m := range upper_masks {
                
				i := net.IP(ip).Mask(net.IPMask(m))
				bignet, ok := mask_ip_hash[string(m)][string(i)]
				if ok {
					subnet.up = bignet
					break
				}
			}
		}
	}

	// Propagate content of attribute opt_networks to all subnets.
   // Go from large to smaller networks.
	sort.Sort((ByMask(mask_list)))
	for _, mask := range mask_list {
		for _, network := range mask_ip_hash[string(mask)] {
			up := network.up
			if up == nil { continue }
			if opt_networks := up.opt_networks; opt_networks {
				network.opt_networks = opt_networks
			}
		}
	}
}

func mark_supernets_of_need_protect (need_protect []*IP_Net) {
	for _, intf := range need_protect {
		up := intf.up
		for up != nil {
			if up.is_supernet_of_need_protect == nil {
				up.is_supernet_of_need_protect = make(map[*IP_Net]bool)
			}
			up.is_supernet_of_need_protect[intf] = true
			up = up.up
		}
	}
}

/*
# Needed for model=Linux.
sub add_tcp_udp_icmp {
    my ($prt2obj) = @_;
    $prt2obj->{'tcp 1 65535'} ||= create_prt_obj('tcp 1 65535');
    $prt2obj->{'udp 1 65535'} ||= create_prt_obj('udp 1 65535');
    $prt2obj->{icmp} ||= create_prt_obj('icmp');
}

# Set {up} relation from port range to the smallest port range which
# includes it.
# If no including range is found, link it with next larger protocol.
# Set attribute {has_neighbor} to range adjacent to upper port.
# Abort on overlapping ranges.
sub order_ranges {
    my ($proto, $prt2obj, $up) = @_;
    my @sorted =

      # Sort by low port. If low ports are equal, sort reverse by high port.
      # I.e. larger ranges coming first, if there are multiple ranges
      # with identical low port.
      sort {
             $a->{range}->[0] <=> $b->{range}->[0]
          || $b->{range}->[1] <=> $a->{range}->[1]
      } 
      grep { $_->{proto} eq $proto and not $_->{established} } 
      values %$prt2obj;

    # Check current range [a1, a2] for sub-ranges, starting at position $i.
    # Set attributes {up} and {has_neighbor}.
    # Return position of range which isn't sub-range or undef
    # if end of array is reached.
    my $check_subrange;

    $check_subrange = sub {
        my ($a, $a1, $a2, $i) = @_;
        while (1) {
            return if $i == @sorted;
            my $b = $sorted[$i];
            my ($b1, $b2) = @{ $b->{range} };

            # Neighbors
            # aaaabbbb
            if ($a2 + 1 == $b1) {

                # Mark protocol as candidate for joining of port ranges during
                # optimization.
                $a->{has_neighbor} = $b->{has_neighbor} = 1;

                # Mark other ranges having identical start port.
                my $j = $i + 1;
                while ($j < @sorted) {
                    my $c = $sorted[$j];
                    my $c1 = $c->{range}->[0];
                    $a2 + 1 == $c1 or last;
                    $c->{has_neighbor} = 1;
                    $j++;
                }                    
            }

            # Not related.
            # aaaa    bbbbb
            return $i if $a2 < $b1;

            # $a includes $b.
            # aaaaaaa
            #  bbbbb
            if ($a2 >= $b2) {
                $b->{up} = $a;
                $i = $check_subrange->($b, $b1, $b2, $i + 1);

                # Stop at end of array.
                $i or return;
                next;
            }

            # $a and $b are overlapping.
            # aaaaa
            #   bbbbbb
            # uncoverable statement
            fatal_err("Unexpected overlapping ranges [$a1-$a2] [$b1-$b2]");
        }
    };

    @sorted or return;
    my $index = 0;
    while (1) {
        my $a = $sorted[$index];
        $a->{up} = $up;
        my ($a1, $a2) = @{ $a->{range} };
        $index++;
        $index = $check_subrange->($a, $a1, $a2, $index) or last;
    }
    return;
}

sub setup_prt_relation {
    my ($prt2obj) = @_;
    my $prt_ip = $prt2obj->{ip} ||= create_prt_obj('ip');
    my $icmp_up = $prt2obj->{icmp} || $prt_ip;
    for my $prt (values %$prt2obj) {
        my $proto = $prt->{proto};
        if ($proto eq 'icmp') {
            my ($type, $code) = @{$prt}{qw(type code)};
            if (defined $type) {
                if (defined $prt->{code}) {
                    $prt->{up} = $prt2obj->{"icmp $type"} || $icmp_up;
                }
                else {
                    $prt->{up} = $icmp_up;
                }
            }
            else {
                $prt->{up} = $prt_ip;
            }
        }
            
        # Numeric protocol.
        elsif ($proto =~ /^\d+$/) {
            $prt->{up} = $prt_ip;
        }
    }

    order_ranges('tcp', $prt2obj, $prt_ip);
    order_ranges('udp', $prt2obj, $prt_ip);

    if (my $tcp_establ = $prt2obj->{'tcp 1 65535 established'}) {
        $tcp_establ->{up} = $prt2obj->{'tcp 1 65535'} || $prt_ip;
    }

    return;
}

#sub print_rule {
#    my ($rule) = @_;
#    my ($deny, $src, $dst, $prt) = @{$rule}{qw(deny src dst prt)};
#    my $action = $deny ? 'deny' : 'permit';
#    return "$action $src->{name} $dst->{name} $prt->{name}";
#}

sub optimize_redundant_rules {
    my ($cmp_hash, $chg_hash, $acl_info) = @_;
    my $ip_net2obj = $acl_info->{ip_net2obj};
    my $prt2obj    = $acl_info->{prt2obj};
    my $changed;
    while (my ($deny, $chg_hash) = each %$chg_hash) {
     while (1) {
      if (my $cmp_hash = $cmp_hash->{$deny}) {
       while (my ($src_range_name, $chg_hash) = each %$chg_hash) {
        my $src_range = $prt2obj->{$src_range_name};
        while (1) {
         if (my $cmp_hash = $cmp_hash->{$src_range->{name}}) {
          while (my ($src_name, $chg_hash) = each %$chg_hash) {
           my $src = $ip_net2obj->{$src_name};
           while (1) {
            if (my $cmp_hash = $cmp_hash->{$src->{name}}) {
             while (my ($dst_name, $chg_hash) = each %$chg_hash) {
              my $dst = $ip_net2obj->{$dst_name};
              while (1) {
               if (my $cmp_hash = $cmp_hash->{$dst->{name}}) {
                for my $chg_rule (values %$chg_hash) {
                 next if $chg_rule->{deleted};
                 my $prt = $chg_rule->{prt};
                 my $chg_log = $chg_rule->{log} || '';
                 while (1) {
                  if (my $cmp_rule = $cmp_hash->{$prt->{name}}) {
                   my $cmp_log = $cmp_rule->{log} || '';
                   if ($cmp_rule ne $chg_rule && $cmp_log eq $chg_log) {

#                   debug "del: ", print_rule $chg_rule;
                    $chg_rule->{deleted} = $cmp_rule;
                    $changed = 1;
                    last;
                   }
                  }
                  $prt = $prt ->{up} or last;
                 }
                }
               }
               $dst = $dst->{up} or last;
              }
             }
            }
            $src = $src->{up} or last;
           }
          }
         }
         $src_range = $src_range->{up} or last;
        }
       }
      }
      last if $deny;
      $deny = 1;
     }
    }
    return $changed;
}

sub optimize_rules {
    my ($rules, $acl_info) = @_;
    my $prt_ip = $acl_info->{prt2obj}->{ip};
    
    # For comparing redundant rules.
    my %rule_tree;

    # Fill rule tree.
    my $changed = 0;
    for my $rule (@$rules) {

        my ($src, $dst, $deny, $src_range, $prt) =
            @{$rule}{qw(src dst deny src_range prt)};
        $deny      ||= '';
        $src_range ||= $prt_ip;
        $src = $src->{name};
        $dst = $dst->{name};
        $src_range = $src_range->{name};
        $prt = $prt->{name};

        # Remove duplicate rules.
        if ($rule_tree{$deny}->{$src_range}->{$src}->{$dst}->{$prt}) {
            $rule->{deleted} = 1;
            $changed = 1;
            next;
        }
        $rule_tree{$deny}->{$src_range}->{$src}->{$dst}->{$prt} = $rule;
    }

    my $changed2 =
        optimize_redundant_rules (\%rule_tree, \%rule_tree, $acl_info);
    $changed ||= $changed2;

    # Implement rules as secondary rule, if possible.
    my %secondary_tree;
    my $ip_key = $prt_ip->{name};
  RULE:
    for my $rule (@$rules) {
        $rule->{opt_secondary} or next;
        next if $rule->{deleted};

        my ($src, $dst, $prt) = @{$rule}{qw(src dst prt)};
        next if $src->{no_opt_addrs};
        next if $dst->{no_opt_addrs};

        # Replace obj by supernet.
        if (my $supernet = $src->{opt_networks}) {
            $src = $rule->{src} = $supernet;
        }
        if (my $supernet = $dst->{opt_networks} and not $dst->{need_protect}) {
            $dst = $rule->{dst} = $supernet;
        }

        # Change protocol to IP.
        $rule->{prt} = $prt_ip;

        # Add new rule to secondary_tree. If multiple rules are
        # converted to the same secondary rule, only the first one
        # will be created.
        $src = $src->{name};
        $dst = $dst->{name};
        if ($secondary_tree{''}->{$ip_key}->{$src}->{$dst}->{$ip_key}) {

#           debug("sec delete: ", print_rule $rule);
            $rule->{deleted} = 1;
            $changed = 1;
        }
        else {

#           debug("sec: ", print_rule $rule);
            $secondary_tree{''}->{$ip_key}->{$src}->{$dst}->{$ip_key} = 
                $rule;
        }
    }

    if (keys %secondary_tree) {
        $changed2 = optimize_redundant_rules(\%secondary_tree, 
                                             \%secondary_tree, $acl_info);
        $changed ||= $changed2;
        $changed2 = optimize_redundant_rules(\%secondary_tree, 
                                             \%rule_tree, $acl_info);
        $changed ||= $changed2;
    }

    if ($changed) {
        $rules = [ grep { not $_->{deleted} } @$rules ];
    }
    return $rules;
}

# Join adjacent port ranges.
sub join_ranges {
    my ($rules, $prt2obj) = @_;
    my $changed;
    my %rule_tree = ();
  RULE:
    for my $rule (@$rules) {
        my ($deny, $src, $dst, $src_range, $prt) =
            @{$rule}{qw(deny src dst src_range prt)};

        # Only ranges which have a neighbor may be successfully optimized.
        # Currently only dst_ranges are handled.
        $prt->{has_neighbor} or next;

        $deny      ||= '';
        $src_range ||= '';
        $rule_tree{$deny}->{$src}->{$dst}->{$src_range}->{$prt} = $rule;
    }

    # %rule_tree is {deny => href, ...}
    for my $href (values %rule_tree) {

        # $href is {src => href, ...}
        for my $href (values %$href) {

            # $href is {dst => href, ...}
            for my $href (values %$href) {

                # $href is {src_range => href, ...}
                for my $src_range_ref (keys %$href) {
                    my $href = $href->{$src_range_ref};

                    # Nothing to do if only a single rule.
                    next if values %$href == 1;

                    # Values of %$href are rules with identical
                    # deny/src/dst/src_range and a TCP or UDP protocol.
                    #
                    # Collect rules with identical log type and
                    # identical protocol.
                    my %key2rules;
                    for my $rule (values %$href) {
                        my $key = $rule->{prt}->{proto};
                        if (my $log = $rule->{log}) {
                            $key .= ",$log";
                        }
                        push @{ $key2rules{$key} }, $rule;
                    }

                    for my $rules (values %key2rules) {

                        # When sorting these rules by low port number,
                        # rules with adjacent protocols will placed
                        # side by side. There can't be overlaps,
                        # because they have been split in function
                        # 'order_ranges'. There can't be sub-ranges,
                        # because they have been deleted as redundant
                        # already.
                        my @sorted = sort {
                            $a->{prt}->{range}->[0]
                                <=> $b->{prt}->{range}->[0]
                        } @$rules;
                        @sorted >= 2 or next;
                        my $i      = 0;
                        my $rule_a = $sorted[$i];
                        my ($a1, $a2) = @{ $rule_a->{prt}->{range} };
                        while (++$i < @sorted) {
                            my $rule_b = $sorted[$i];
                            my ($b1, $b2) = @{ $rule_b->{prt}->{range} };
                            if ($a2 + 1 == $b1) {
                                
                                # Found adjacent port ranges.
                                if (my $range = delete $rule_a->{range}) {
                                    
                                    # Extend range of previous two or
                                    # more elements.
                                    $range->[1] = $b2;
                                    $rule_b->{range} = $range;
                                }
                                else {
                                    
                                    # Combine ranges of $rule_a and $rule_b.
                                    $rule_b->{range} = [ $a1, $b2 ];
                                }
                                
                                # Mark previous rule as deleted.
                                $rule_a->{deleted} = 1;
                                $changed = 1;
                            }
                            $rule_a = $rule_b;
                            ($a1, $a2) = ($b1, $b2);
                        }
                    }
                }
            }
        }
    }
    if ($changed) {
        my @rules;
        for my $rule (@$rules) {

            # Check and remove attribute 'deleted'.
            next if delete $rule->{deleted};

            # Process rules with joined port ranges.
            # Remove auxiliary attribute {range} from rules.
            if (my $range = delete $rule->{range}) {
                my $proto = $rule->{prt}->{proto};
                my $key   = "$proto $range->[0] $range->[1]";

                # Try to find existing prt with matching range.
                # This is needed for find_objectgroups to work.
                my $new_prt = $prt2obj->{$key};
                if (not $new_prt) {
                    $new_prt = {
                        proto => $proto,
                        range => $range
                    };
                    $prt2obj->{$key} = $new_prt;
                }
                my $new_rule = { %$rule, prt => $new_prt };
                push @rules, $new_rule;
            }
            else {
                push @rules, $rule;
            }
        }
        $rules = \@rules;
    }
    return $rules;
}

# Protocols ESP and AH are be placed first in Cisco ACL
# for performance reasons.
# These rules need to have a fixed order.
# Otherwise the connection may be lost,
# - if the device is accessed over an IPSec tunnel
# - and we change the ACL incrementally.
sub move_rules_esp_ah {
    my ($acl_info) = @_;
    my $prt2obj = $acl_info->{prt2obj};
    my $prt_esp = $prt2obj->{50};
    my $prt_ah  = $prt2obj->{51};
    $prt_esp or $prt_ah or return;
    for my $what (qw(intf_rules rules)) {
        my $rules = $acl_info->{$what} or next;
        my (@deny_rules, @crypto_rules, @permit_rules);
        for my $rule (@$rules) {
            if ($rule->{deny}) {
                push @deny_rules, $rule;
            }
            elsif ($prt_esp and $rule->{prt} eq $prt_esp) {
                push @crypto_rules, $rule;
            }
            elsif ($prt_ah and $rule->{prt} eq $prt_ah) {
                push @crypto_rules, $rule;
            }
            else {
                push @permit_rules, $rule;
            }
        }

        # Sort crypto rules.
        @crypto_rules =
            sort({ my ($s_a, $d_a) = @{$a}{qw(src dst)};
                   my ($s_b, $d_b) = @{$b}{qw(src dst)};
                   $a->{prt}->{proto} <=> $b->{prt}->{proto} ||
                   $s_a->{ip} cmp $s_b->{ip} || $s_a->{mask} cmp $s_b->{mask} ||
                   $d_a->{ip} cmp $d_b->{ip} || $d_a->{mask} cmp $d_b->{mask} } 
                 @crypto_rules);
        $acl_info->{$what} = [ @deny_rules, @crypto_rules, @permit_rules ];
    }
    return;
}

# Add deny and permit rules at device which filters only locally.
sub add_local_deny_rules {
    my ($acl_info, $router_data) = @_;
    my $do_objectgroup = $router_data->{do_objectgroup};
    my ($network_00, $prt_ip) = @{$acl_info}{qw(network_00 prt_ip)};
    my $filter_only = $acl_info->{filter_only};
    my $rules       = $acl_info->{rules};
    
    my $src_networks = 
        $acl_info->{filter_any_src} ? [$network_00] : $filter_only;

    if ($do_objectgroup) {

        my $group_or_single = sub {
            my ($obj_list) = @_;
            if (1 == @$obj_list) {
                return $obj_list->[0];
            }

            # Reuse object-group at all interfaces.
            elsif (my $group = $router_data->{filter_only_group}) {
                return $group;
            }
            else {
                $group = { name => "g$router_data->{obj_group_counter}",
                           elements => $obj_list };
                $router_data->{obj_group_counter}++;
                push @{ $acl_info->{object_groups} }, $group;
                $router_data->{filter_only_group} = $group;
                return $group;
            }
        };
        push(@$rules, 
             { deny => 1, 
               src => $group_or_single->($src_networks), 
               dst => $group_or_single->($filter_only), 
               prt => $prt_ip });
    }
    else {
        for my $src (@$src_networks) {
            for my $dst (@$filter_only) {
                push(@$rules,
                     { deny => 1, src => $src, dst => $dst, prt => $prt_ip });
            }
        }
    }
    push @$rules, { src => $network_00, dst => $network_00, prt => $prt_ip };
    return;
}

##############################################################################
# Purpose    : Create a list of IP/mask objects from a hash of IP/mask names.
#              Adjacent IP/mask objects are combined to larger objects.
#              It is assumed, that no duplicate or redundant IP/mask objects
#              are given.
# Parameters : $hash - hash with IP/mask names as keys and 
#                      IP/mask objects as values.
#              $ip_net2obj - hash of all known IP/mask objects
# Result     : Returns reference to array of sorted and combined 
#              IP/mask objects.
#              Parameter $hash is changed to reflect combined IP/mask objects.
sub combine_adjacent_ip_mask {
    my ($hash, $ip_net2obj) = @_;

    # Convert names to objects.
    # Sort by mask. Adjacent networks will be adjacent elements then.
    my $elements = [
        sort { $a->{ip} cmp $b->{ip} || $a->{mask} cmp $b->{mask} }
        map { $ip_net2obj->{$_} }
        keys %$hash ];

    # Find left and rigth part with identical mask and combine them
    # into next larger network.
    # Compare up to last but one element.
    for (my $i = 0 ; $i < @$elements - 1 ; $i++) {
        my $element1 = $elements->[$i];
        my $element2 = $elements->[$i+1];
        my $mask = $element1->{mask};
        $mask eq $element2->{mask} or next;
        my $prefix = mask2prefix($mask);
        my $up_mask = prefix2mask($prefix-1);
        my $ip = $element1->{ip};
        ($ip & $up_mask) eq ($element2->{ip} & $up_mask) or next;
        my $up_element = get_ip_obj($ip, $up_mask, $ip_net2obj);

        # Substitute left part by combined network.
        $elements->[$i] = $up_element;

        # Remove right part.
        splice @$elements, $i+1, 1;

        # Add new element and remove left and rigth parts.
        $hash->{$up_element->{name}} = $up_element;
        delete $hash->{$element1->{name}};
        delete $hash->{$element2->{name}};

        if ($i > 0) {
            my $next_bit = increment_ip(~$up_mask);

            # Check previous network again, if newly created network
            # is left part.
            $i-- if ($ip & $next_bit);
        }

        # Only one element left.
        # Condition of for-loop isn't effective, because of 'redo' below.
        last if $i >= @$elements - 1;

        # Compare current network again.
        redo;
    }
    return $elements;
}

my $min_object_group_size = 2;

sub find_objectgroups {
    my ($acl_info, $router_data) = @_;
    my $ip_net2obj = $acl_info->{ip_net2obj};

    # Reuse identical groups from different ACLs.
    my $size2first2group = $router_data->{obj_groups_hash} ||= {};
    $router_data->{obj_group_counter} ||= 0;

    # Leave 'intf_rules' untouched, because
    # - these rules are ignored at ASA,
    # - NX-OS needs them individually when optimizing need_protect.
    my $rules = $acl_info->{rules};

    # Find object-groups in src / dst of rules.
    for my $this ('src', 'dst') {
        my $that = $this eq 'src' ? 'dst' : 'src';
        my %group_rule_tree;

        # Find groups of rules with identical
        # deny, src_range, prt, log, src/dst and different dst/src.
        for my $rule (@$rules) {
            my $deny      = $rule->{deny} || '';
            my $that      = $rule->{$that}->{name};
            my $this      = $rule->{$this}->{name};
            my $src_range = $rule->{src_range} || '';
            my $prt       = $rule->{prt};
            my $key       = "$deny,$that,$src_range,$prt";
            if (my $log = $rule->{log}) {
                $key .= ",$log";
            }
            $group_rule_tree{$key}->{$this} = $rule;
        }

        # Find groups >= $min_object_group_size,
        # mark rules belonging to one group.
        for my $href (values %group_rule_tree) {

            # $href is {dst/src => rule, ...}
            keys %$href >= $min_object_group_size or next;

            my $glue = {

                # Indicator, that group has already beed added to some rule.
                active => 0,

                # object-key => rule, ...
                hash => $href
            };

            # All this rules have identical deny, src_range, prt
            # and dst/src and shall be replaced by a single new
            # rule referencing an object group.
            for my $rule (values %$href) {
                $rule->{group_glue} = $glue;
            }
        }

        # Find group with identical elements or define a new one.
        my $get_group = sub {
            my ($hash) = @_;

            # Get sorted and combined list of objects from hash of names.
            my $elements = combine_adjacent_ip_mask($hash, $ip_net2obj);

            # If all elements have been combined into one single network,
            # don't create a group, but take single element as result.
            if (1 == @$elements) {
                return $elements->[0];
            }

            # Use size and first element as keys for efficient hashing.
            my $size  = @$elements;
            my $first = $elements->[0]->{name};

            # Search group with identical elements.
          HASH:
            for my $group (@{ $size2first2group->{$size}->{$first} }) {
                my $href = $group->{hash};

                # Check elements for equality.
                for my $key (keys %$hash) {
                    $href->{$key} or next HASH;
                }

                # Found $group with matching elements.
                return $group;
            }

            # No group found, build new group.
            my $group = { name     => "g$router_data->{obj_group_counter}", 
                          elements => $elements,
                          hash     => $hash, };
            $router_data->{obj_group_counter}++;

            # Store group for later printing of its definition.
            push @{ $acl_info->{object_groups} }, $group;
            push(@{ $size2first2group->{$size}->{$first} }, $group);
            return $group;
        };

        # Build new list of rules using object groups.
        my @new_rules;
        for my $rule (@$rules) {
            if (my $glue = delete $rule->{group_glue}) {
                next if $glue->{active};
                $glue->{active} = 1;
                my $group = $get_group->($glue->{hash});
                $rule->{$this} = $group;
            }
            push @new_rules, $rule;
        }
        $rules = \@new_rules;
    }
    $acl_info->{rules} = $rules;
    return;
}

sub add_protect_rules {
    my ($acl_info, $router_data, $has_final_permit) = @_;
    my $need_protect = $acl_info->{need_protect} or return;
    my ($network_00, $prt_ip) = @{$acl_info}{qw(network_00 prt_ip)};

    # Add deny rules to protect own interfaces.
    # If a rule permits traffic to a directly connected network behind
    # the device, this would accidently permit traffic to an interface
    # of this device as well.

    # To be added deny rule is needless if there is a rule which
    # permits any traffic to the interface.
    # This permit rule can be deleted if there is a permit any any rule.
    my %no_protect;
    my $changed;
    for my $rule (@{ $acl_info->{intf_rules} }) {
        next if $rule->{deny};
        next if $rule->{src} ne $network_00;
        next if $rule->{prt} ne $prt_ip;
        my $dst = $rule->{dst};
        $no_protect{$dst} = 1 if $dst->{need_protect};

        if ($has_final_permit) {
            $rule    = undef;
            $changed = 1;
        }
    }
    if ($changed) {
        $acl_info->{intf_rules} = [ grep { $_ } @{ $acl_info->{intf_rules} } ];
    }

    # Deny rule is needless if there is no such permit rule.
    # Try to optimize this case.
    my %need_protect;
    for my $rule (@{ $acl_info->{rules} }) {
        next if $rule->{deny};
        next if $rule->{prt}->{established};
        my $dst = $rule->{dst};
        my $hash = $dst->{is_supernet_of_need_protect} or next;
        for my $intf (@$need_protect) {
            if ($hash->{$intf}) {
                $need_protect{$intf} = $intf;
            }
        }
    }

    # Protect own interfaces.
    for my $interface (@$need_protect) {
        if (    $no_protect{$interface}
            or  not $need_protect{$interface}
            and not $has_final_permit)
        {
            next;
        }

        push @{ $acl_info->{intf_rules} }, {
            deny => 1,
            src  => $network_00,
            dst  => $interface,
            prt  => $prt_ip
        };
    }
}

# Check if last is rule is 'permit ip any any'.
sub check_final_permit {
    my ($acl_info, $router_data) = @_;
    my $rules = $acl_info->{rules};
    $rules and @$rules or return;
    my ($net_00, $prt_ip) = @{$acl_info}{qw(network_00 prt_ip)};
    my ($deny, $src, $dst, $prt) = @{ $rules->[-1] }{qw(deny src dst prt)};
    return !$deny && $src eq $net_00 && $dst eq $net_00 && $prt eq $prt_ip;
}

# Add 'deny|permit ip any any' at end of ACL.
sub add_final_permit_deny_rule {
    my ($acl_info, $router_data) = @_;
    my $rules = $acl_info->{rules};
    $acl_info->{add_deny} or $acl_info->{add_permit} or return;

    my ($net_00, $prt_ip) = @{$acl_info}{qw(network_00 prt_ip)};
    my $rule = { src => $net_00, dst => $net_00, prt => $prt_ip };
    if ($acl_info->{add_deny}) {
        $rule->{deny} = 1;
    }
    push @{ $acl_info->{rules} }, $rule;

    return;
}

# Returns iptables code for filtering a protocol.
sub iptables_prt_code {
    my ($src_range, $prt) = @_;
    my $proto = $prt->{proto};

    if ($proto eq 'tcp' or $proto eq 'udp') {
        my $port_code = sub {
            my ($range_obj) = @_;
            my ($v1, $v2) = @{ $range_obj->{range} };
            if ($v1 == $v2) {
                return $v1;
            }
            elsif ($v1 == 1 and $v2 == 65535) {
                return '';
            }
            elsif ($v2 == 65535) {
                return "$v1:";
            }
            elsif ($v1 == 1) {
                return ":$v2";
            }
            else {
                return "$v1:$v2";
            }
        };
        my $result = "-p $proto";
        my $sport = $src_range && $port_code->($src_range);
        $result .= " --sport $sport" if $sport;
        my $dport = $port_code->($prt);
        $result .= " --dport $dport" if $dport;
        return $result;
    }
    elsif ($proto eq 'icmp') {
        if (defined(my $type = $prt->{type})) {
            if (defined(my $code = $prt->{code})) {
                return "-p $proto --icmp-type $type/$code";
            }
            else {
                return "-p $proto --icmp-type $type";
            }
        }
        else {
            return "-p $proto";
        }
    }
    else {
        return "-p $proto";
    }
}


# Handle iptables.
#
#sub debug_bintree {
#    my ($tree, $depth) = @_;
#    $depth ||= '';
#    my $ip      = bitstr($tree->{ip});
#    my $mask    = mask2prefix($tree->{mask});
#    my $subtree = $tree->{subtree} ? 'subtree' : '';
#
#    debug($depth, " $ip/$mask $subtree");
#    debug_bintree($tree->{lo}, "${depth}l") if $tree->{lo};
#    debug_bintree($tree->{hi}, "${depth}h") if $tree->{hi};
#    return;
#}

# Nodes are reverse sorted before being added to bintree.
# Redundant nodes are discarded while inserting.
# A node with value of sub-tree S is discarded,
# if some parent node already has sub-tree S.
sub add_bintree;
sub add_bintree {
    my ($tree,    $node)      = @_;
    my ($tree_ip, $tree_mask) = @{$tree}{qw(ip mask)};
    my ($node_ip, $node_mask) = @{$node}{qw(ip mask)};
    my $result;

    # The case where new node is larger than root node will never
    # occur, because nodes are sorted before being added.

    if ($tree_mask lt $node_mask && match_ip($node_ip, $tree_ip, $tree_mask)) {

        # Optimization for this special case:
        # Root of tree has attribute {subtree} which is identical to
        # attribute {subtree} of current node.
        # Node is known to be less than root node.
        # Hence node together with its subtree can be discarded
        # because it is redundant compared to root node.
        # ToDo:
        # If this optimization had been done before merge_subtrees,
        # it could have merged more subtrees.
        if (   not $tree->{subtree}
            or not $node->{subtree}
            or $tree->{subtree} ne $node->{subtree})
        {
            my $prefix = mask2prefix($tree_mask);
            my $mask = prefix2mask($prefix+1);
            my $branch = match_ip($node_ip, $tree_ip, $mask) ? 'lo' : 'hi';
            if (my $subtree = $tree->{$branch}) {
                $tree->{$branch} = add_bintree $subtree, $node;
            }
            else {
                $tree->{$branch} = $node;
            }
        }
        $result = $tree;
    }

    # Create common root for tree and node.
    else {
        while (1) {
            my $prefix = mask2prefix($tree_mask);
            $tree_mask = prefix2mask($prefix-1);
            last if ($node_ip & $tree_mask) eq ($tree_ip & $tree_mask);
        }
        $result = {
            ip   => ($node_ip & $tree_mask),
            mask => $tree_mask
        };
        @{$result}{qw(lo hi)} =
          $node_ip lt $tree_ip ? ($node, $tree) : ($tree, $node);
    }

    # Merge adjacent sub-networks.
  MERGE:
    {
        $result->{subtree} and last;
        my $lo = $result->{lo} or last;
        my $hi = $result->{hi} or last;
        my $prefix = mask2prefix($result->{mask});
        my $mask = prefix2mask($prefix+1);
        $lo->{mask} eq $mask or last;
        $hi->{mask} eq $mask or last;
        $lo->{subtree} and $hi->{subtree} or last;
        $lo->{subtree} eq $hi->{subtree} or last;

        for my $key (qw(lo hi)) {
            $lo->{$key} and last MERGE;
            $hi->{$key} and last MERGE;
        }

#       debug('Merged: ', print_ip $lo->{ip},' ',
#             print_ip $hi->{ip},'/',print_ip $hi->{mask});
        $result->{subtree} = $lo->{subtree};
        delete $result->{lo};
        delete $result->{hi};
    }
    return $result;
}

# Build a binary tree for src/dst objects.
sub gen_addr_bintree {
    my ($elements, $tree) = @_;

    # Sort in reverse order by mask and then by IP.
    my @nodes =
      sort { $b->{mask} cmp $a->{mask} || $b->{ip} cmp $a->{ip} }
      map {
        my ($ip, $mask) = @{$_}{qw(ip mask)};

        # The tree's node is a simplified network object with
        # missing attribute 'name' and extra 'subtree'.
        { ip      => $ip,
          mask    => $mask,
          subtree => $tree->{$_->{name}}
        }
      } @$elements;
    my $bintree = pop @nodes;
    while (my $next = pop @nodes) {
        $bintree = add_bintree $bintree, $next;
    }

    # Add attribute {noop} to node which doesn't add any test to
    # generated rule.
    $bintree->{noop} = 1 if $bintree->{mask} eq $zero_ip;

#    debug_bintree($bintree);
    return $bintree;
}

# Build a tree for src-range/prt objects. Sub-trees for tcp and udp
# will be binary trees. Nodes have attributes {proto}, {range},
# {type}, {code} like protocols (but without {name}).
# Additional attributes for building the tree:
# For tcp and udp:
# {lo}, {hi} for sub-ranges of current node.
# For other protocols:
# {seq} an array of ordered nodes for sub protocols of current node.
# Elements of {lo} and {hi} or elements of {seq} are guaranteed to be
# disjoint.
# Additional attribute {subtree} is set with corresponding subtree of
# protocol object if current node comes from a rule and wasn't inserted
# for optimization.
sub gen_prt_bintree {
    my ($elements, $tree) = @_;

    my $ip_prt;
    my (%top_prt, %sub_prt);

    # Add all protocols directly below protocol 'ip' into hash %top_prt
    # grouped by protocol. Add protocols below top protocols or below
    # other protocols of current set of protocols to hash %sub_prt.
  PRT:
    for my $prt (@$elements) {
        my $proto = $prt->{proto};
        if ($proto eq 'ip') {
            $ip_prt = $prt;
            next PRT;
        }

        my $up = $prt->{up};

        # Check if $prt is sub protocol of any other protocol of
        # current set. But handle direct sub protocols of 'ip' as top
        # protocols.
        while ($up->{up}) {
            if (my $subtree = $tree->{$up->{name}}) {

                # Found sub protocol of current set.
                # Optimization:
                # Ignore the sub protocol if both protocols have
                # identical subtrees.
                # In this case we found a redundant sub protocol.
                if ($tree->{$prt->{name}} ne $subtree) {
                    push @{ $sub_prt{$up} }, $prt;
                }
                next PRT;
            }
            $up = $up->{up};
        }

        # Not a sub protocol (except possibly of IP).
        my $key = $proto =~ /^\d+$/ ? 'proto' : $proto;
        push @{ $top_prt{$key} }, $prt;
    }

    # Collect subtrees for tcp, udp, proto and icmp.
    my @seq;

# Build subtree of tcp and udp protocols.
    #
    # We need not to handle 'tcp established' because it is only used
    # for stateless routers, but iptables is stateful.
    my ($gen_lohitrees, $gen_rangetree);
    $gen_lohitrees = sub {
        my ($prt_aref) = @_;
        if (not $prt_aref) {
            return (undef, undef);
        }
        elsif (@$prt_aref == 1) {
            my $prt = $prt_aref->[0];
            my ($lo, $hi) = $gen_lohitrees->($sub_prt{$prt});
            my $node = {
                proto   => $prt->{proto},
                range   => $prt->{range},
                subtree => $tree->{$prt->{name}},
                lo      => $lo,
                hi      => $hi
            };
            return ($node, undef);
        }
        else {
            my @ranges =
              sort { $a->{range}->[0] <=> $b->{range}->[0] } @$prt_aref;

            # Split array in two halves.
            my $mid   = int($#ranges / 2);
            my $left  = [ @ranges[ 0 .. $mid ] ];
            my $right = [ @ranges[ $mid + 1 .. $#ranges ] ];
            return ($gen_rangetree->($left), $gen_rangetree->($right));
        }
    };
    $gen_rangetree = sub {
        my ($prt_aref) = @_;
        my ($lo, $hi) = $gen_lohitrees->($prt_aref);
        return $lo if not $hi;
        my $proto = $lo->{proto};

        # Take low port from lower tree and high port from high tree.
        my $range = [ $lo->{range}->[0], $hi->{range}->[1] ];

        # Merge adjacent port ranges.
        if (    $lo->{range}->[1] + 1 == $hi->{range}->[0]
            and $lo->{subtree}
            and $hi->{subtree}
            and $lo->{subtree} eq $hi->{subtree})
        {
            my @hilo =
              grep { defined $_ } $lo->{lo}, $lo->{hi}, $hi->{lo}, $hi->{hi};
            if (@hilo <= 2) {

#		debug("Merged: $lo->{range}->[0]-$lo->{range}->[1]",
#		      " $hi->{range}->[0]-$hi->{range}->[1]");
                my $node = {
                    proto   => $proto,
                    range   => $range,
                    subtree => $lo->{subtree}
                };
                $node->{lo} = shift @hilo if @hilo;
                $node->{hi} = shift @hilo if @hilo;
                return $node;
            }
        }
        return (
            {
                proto => $proto,
                range => $range,
                lo    => $lo,
                hi    => $hi
            }
        );
    };
    for my $what (qw(tcp udp)) {
        next if not $top_prt{$what};
        push @seq, $gen_rangetree->($top_prt{$what});
    }

# Add single nodes for numeric protocols.
    if (my $aref = $top_prt{proto}) {
        for my $prt (sort { $a->{proto} <=> $b->{proto} } @$aref) {
            my $node = { proto => $prt->{proto}, subtree => $tree->{$prt->{name}} };
            push @seq, $node;
        }
    }

# Build subtree of icmp protocols.
    if (my $icmp_aref = $top_prt{icmp}) {
        my %type2prt;
        my $icmp_any;

        # If one protocol is 'icmp any' it is the only top protocol,
        # all other icmp protocols are sub protocols.
        if (not defined $icmp_aref->[0]->{type}) {
            $icmp_any  = $icmp_aref->[0];
            $icmp_aref = $sub_prt{$icmp_any};
        }

        # Process icmp protocols having defined type and possibly defined code.
        # Group protocols by type.
        for my $prt (@$icmp_aref) {
            my $type = $prt->{type};
            push @{ $type2prt{$type} }, $prt;
        }

        # Parameter is array of icmp protocols all having
        # the same type and different but defined code.
        # Return reference to array of nodes sorted by code.
        my $gen_icmp_type_code_sorted = sub {
            my ($aref) = @_;
            [
                map {
                    {
                        proto   => 'icmp',
                        type    => $_->{type},
                        code    => $_->{code},
                        subtree => $tree->{$_->{name}}
                    }
                  }
                  sort { $a->{code} <=> $b->{code} } @$aref
            ];
        };

        # For collecting subtrees of icmp subtree.
        my @seq2;

        # Process grouped icmp protocols having the same type.
        for my $type (sort { $a <=> $b } keys %type2prt) {
            my $aref2 = $type2prt{$type};
            my $node2;

            # If there is more than one protocol,
            # all have same type and defined code.
            if (@$aref2 > 1) {
                my $seq3 = $gen_icmp_type_code_sorted->($aref2);

                # Add a node 'icmp type any' as root.
                $node2 = {
                    proto => 'icmp',
                    type  => $type,
                    seq   => $seq3,
                };
            }

            # One protocol 'icmp type any'.
            else {
                my $prt = $aref2->[0];
                $node2 = {
                    proto   => 'icmp',
                    type    => $type,
                    subtree => $tree->{$prt->{name}}
                };
                if (my $aref3 = $sub_prt{$prt}) {
                    $node2->{seq} = $gen_icmp_type_code_sorted->($aref3);
                }
            }
            push @seq2, $node2;
        }

        # Add root node for icmp subtree.
        my $node;
        if ($icmp_any) {
            $node = {
                proto   => 'icmp',
                seq     => \@seq2,
                subtree => $tree->{$icmp_any->{name}}
            };
        }
        elsif (@seq2 > 1) {
            $node = { proto => 'icmp', seq => \@seq2 };
        }
        else {
            $node = $seq2[0];
        }
        push @seq, $node;
    }

# Add root node for whole tree.
    my $bintree;
    if ($ip_prt) {
        $bintree = {
            proto   => 'ip',
            seq     => \@seq,
            subtree => $tree->{$ip_prt->{name}}
        };
    }
    elsif (@seq > 1) {
        $bintree = { proto => 'ip', seq => \@seq };
    }
    else {
        $bintree = $seq[0];
    }

    # Add attribute {noop} to node which doesn't need any test in
    # generated chain.
    $bintree->{noop} = 1 if $bintree->{proto} eq 'ip';
    return $bintree;
}

sub find_chains {
    my ($acl_info, $router_data) = @_;
    my $rules      = $acl_info->{rules};
    my $ip_net2obj = $acl_info->{ip_net2obj};
    my $prt2obj    = $acl_info->{prt2obj};
    my %ref_type = (
        src       => $ip_net2obj,
        dst       => $ip_net2obj,
        src_range => $prt2obj,
        prt       => $prt2obj,
    );

    my $prt_ip     = $prt2obj->{ip};
    my $prt_icmp   = $prt2obj->{icmp};
    my $prt_tcp    = $prt2obj->{'tcp 1 65535'};
    my $prt_udp    = $prt2obj->{'udp 1 65535'};
    my $network_00 = $ip_net2obj->{'0.0.0.0/0'};

    # For generating names of chains.
    # Initialize if called first time.
    $router_data->{chain_counter} ||= 1;

    # Set {action} attribute in $rule, so we can handle all properties
    # of a rule in unified manner.
    # Change {src_range} attribute.
    for my $rule (@$rules) {
        if (!$rule->{action}) {
            $rule->{action} = $rule->{deny} ? 'deny' : 'permit';
        }
        my $src_range = $rule->{src_range};
        if (not $src_range) {
            my $proto = $rule->{prt}->{proto};

            # Specify protocols tcp, udp, icmp in
            # {src_range}, to get more efficient chains.
            $src_range =
                $proto eq 'tcp'  ? $prt_tcp
              : $proto eq 'udp'  ? $prt_udp
              : $proto eq 'icmp' ? $prt_icmp
              :                    $prt_ip;
            $rule->{src_range} = $src_range;
        }
    }

    my %cache;

#    my $print_tree;
#    $print_tree = sub {
#        my ($tree, $order, $depth) = @_;
#        for my $name (keys %$tree) {
#
#            debug(' ' x $depth, $name);
#            if ($depth < $#$order) {
#                $print_tree->($tree->{$name}, $order, $depth + 1);
#            }
#        }
#    };

    my $insert_bintree = sub {
        my ($tree, $order, $depth) = @_;
        my $key      = $order->[$depth];
        my $ref2x    = $ref_type{$key};
        my @elements = map { $ref2x->{$_} } keys %$tree;

        # Put prt/src/dst objects at the root of some subtree into a
        # (binary) tree. This is used later to convert subsequent tests
        # for ip/mask or port ranges into more efficient nested chains.
        my $bintree;
        if ($ref2x eq $ip_net2obj) {
            $bintree = gen_addr_bintree(\@elements, $tree);
        }
        else {    # $ref2x eq $prt2obj
            $bintree = gen_prt_bintree(\@elements, $tree);
        }
        return $bintree;
    };

    # Used by $merge_subtrees1 to find identical subtrees.
    # Use hash for efficient lookup.
    my %depth2size2subtrees;
    my %subtree2bintree;

    # Find and merge identical subtrees.
    my $merge_subtrees1 = sub {
        my ($tree, $order, $depth) = @_;

      SUBTREE:
        for my $subtree (values %$tree) {
            my @keys = keys %$subtree;
            my $size = @keys;

            # Find subtree with identical keys and values;
          FIND:
            for my $subtree2 (@{ $depth2size2subtrees{$depth}->{$size} }) {
                for my $key (@keys) {
                    if (not $subtree2->{$key}
                        or $subtree2->{$key} ne $subtree->{$key})
                    {
                        next FIND;
                    }
                }

                # Substitute current subtree with found subtree.
                $subtree = $subtree2bintree{$subtree2};
                next SUBTREE;

            }

            # Found a new subtree.
            push @{ $depth2size2subtrees{$depth}->{$size} }, $subtree;
            $subtree = $subtree2bintree{$subtree} =
              $insert_bintree->($subtree, $order, $depth + 1);
        }
    };

    my $merge_subtrees = sub {
        my ($tree, $order) = @_;

        # Process leaf nodes first.
        for my $href (values %$tree) {
            for my $href (values %$href) {
                $merge_subtrees1->($href, $order, 2);
            }
        }

        # Process nodes next to leaf nodes.
        for my $href (values %$tree) {
            $merge_subtrees1->($href, $order, 1);
        }

        # Process nodes next to root.
        $merge_subtrees1->($tree, $order, 0);
        return $insert_bintree->($tree, $order, 0);
    };

    # Add new chain to current router.
    my $new_chain = sub {
        my ($rules) = @_;
        my $counter = $router_data->{chain_counter}++;
        my $chain   = { name  => "c$counter", rules => $rules, };
        push @{ $router_data->{chains} }, $chain;
        return $chain;
    };

    my $gen_chain;
    $gen_chain = sub {
        my ($tree, $order, $depth) = @_;
        my $key = $order->[$depth];
        my @rules;

        # We need the original value later.
        my $bintree = $tree;
        while (1) {
            my ($hi, $lo, $seq, $subtree) =
              @{$bintree}{qw(hi lo seq subtree)};
            $seq = undef if $seq and not @$seq;
            if (not $seq) {
                push @$seq, $hi if $hi;
                push @$seq, $lo if $lo;
            }
            if ($subtree) {

#               if($order->[$depth+1]&&
#                  $order->[$depth+1] =~ /^(src|dst)$/) {
#                   debug($order->[$depth+1]);
#                   debug_bintree($subtree);
#               }
                my $rules = $cache{$subtree};
                if (not $rules) {
                    $rules =
                      $depth + 1 >= @$order
                      ? [ { action => $subtree } ]
                      : $gen_chain->($subtree, $order, $depth + 1);
                    if (@$rules > 1 and not $bintree->{noop}) {
                        my $chain = $new_chain->($rules);
                        $rules = [ { action => $chain, goto => 1 } ];
                    }
                    $cache{$subtree} = $rules;
                }

                my @add_keys;

                # Don't use "goto", if some tests for sub-nodes of
                # $subtree are following.
                push @add_keys, (goto => 0)        if $seq;
                push @add_keys, ($key => $bintree) if not $bintree->{noop};
                if (@add_keys) {

                    # Create a copy of each rule because we must not change
                    # the original cached rules.
                    push @rules, map {
                        { (%$_, @add_keys) }
                    } @$rules;
                }
                else {
                    push @rules, @$rules;
                }
            }
            last if not $seq;

            # Take this value in next iteration.
            $bintree = pop @$seq;

            # Process remaining elements.
            for my $node (@$seq) {
                my $rules = $gen_chain->($node, $order, $depth);
                push @rules, @$rules;
            }
        }
        if (@rules > 1 and not $tree->{noop}) {

            # Generate new chain. All elements of @seq are
            # known to be disjoint. If one element has matched
            # and branched to a chain, then the other elements
            # need not be tested again. This is implemented by
            # calling the chain using '-g' instead of the usual '-j'.
            my $chain = $new_chain->(\@rules);
            return [ { action => $chain, goto => 1, $key => $tree } ];
        }
        else {
            return \@rules;
        }
    };

    # Build rule trees. Generate and process separate tree for
    # adjacent rules with same action.
    my @rule_trees;
    my %tree2order;
    if (@$rules) {
        my $prev_action = $rules->[0]->{action};

        # Special rule as marker, that end of rules has been reached.
        push @$rules, { action => 0 };
        my $start = my $i = 0;
        my $last = $#$rules;
        my %count;
        while (1) {
            my $rule   = $rules->[$i];
            my $action = $rule->{action};
            if ($action eq $prev_action) {

                # Count, which key has the largest number of
                # different values.
                for my $what (qw(src dst src_range prt)) {
                    $count{$what}{ $rule->{$what} } = 1;
                }
                $i++;
            }
            else {

                # Use key with smaller number of different values
                # first in rule tree. This gives smaller tree and
                # fewer tests in chains.
                my @test_order =
                  sort { keys %{ $count{$a} } <=> keys %{ $count{$b} } }
                  qw(src_range dst prt src);
                my $rule_tree;
                my $end = $i - 1;
                for (my $j = $start ; $j <= $end ; $j++) {
                    my $rule = $rules->[$j];
                    my ($action, $t1, $t2, $t3, $t4) =
                      @{$rule}{ 'action', @test_order };
                    ($t1, $t2, $t3, $t4) = 
                        map { $_->{name} } ($t1, $t2, $t3, $t4);
                    $rule_tree->{$t1}->{$t2}->{$t3}->{$t4} = $action;
                }
                push @rule_trees, $rule_tree;

#   	    debug(join ', ', @test_order);
                $tree2order{$rule_tree} = \@test_order;
                last if not $action;
                $start       = $i;
                $prev_action = $action;
            }
        }
        @$rules = ();
    }

    for (my $i = 0 ; $i < @rule_trees ; $i++) {
        my $tree  = $rule_trees[$i];
        my $order = $tree2order{$tree};

#       $print_tree->($tree, $order, 0);
        $tree = $merge_subtrees->($tree, $order);
        my $result = $gen_chain->($tree, $order, 0);

        # Goto must not be used in last rule of rule tree which is
        # not the last tree.
        if ($i != $#rule_trees) {
            my $rule = $result->[-1];
            delete $rule->{goto};
        }

        # Postprocess rules: Add missing attributes prt, src, dst
        # with no-op values.
        for my $rule (@$result) {
            $rule->{src} ||= $network_00;
            $rule->{dst} ||= $network_00;
            my $prt     = $rule->{prt};
            my $src_range = $rule->{src_range};
            if (not $prt and not $src_range) {
                $rule->{prt} = $prt_ip;
            }
            elsif (not $prt) {
                $rule->{prt} =
                    $src_range->{proto} eq 'tcp'  ? $prt_tcp
                  : $src_range->{proto} eq 'udp'  ? $prt_udp
                  : $src_range->{proto} eq 'icmp' ? $prt_icmp
                  :                                 $prt_ip;
            }
        }
        push @$rules, @$result;
    }
    $acl_info->{rules} = $rules;
    return;
}

# Given an IP and mask, return its address
# as "x.x.x.x/x" or "x.x.x.x" if prefix == 32.
sub prefix_code {
    my ($ip_net) = @_;
    my ($ip, $mask) = @{$ip_net}{qw(ip mask)};
    my $ip_code     = bitstr2ip($ip);
    my $prefix_code = mask2prefix($mask);
    return $prefix_code == 32 ? $ip_code : "$ip_code/$prefix_code";
}

# Print chains of iptables.
# Objects have already been normalized to ip/mask pairs.
# NAT has already been applied.
sub print_chains {
    my ($router_data) = @_;
    my $chains = $router_data->{chains};
    @$chains or return;

    my $acl_info   = $router_data->{acls}->[0];
    my $prt2obj    = $acl_info->{prt2obj};
    my $prt_ip     = $prt2obj->{ip};
    my $prt_icmp   = $prt2obj->{icmp};
    my $prt_tcp    = $prt2obj->{'tcp 1 65535'};
    my $prt_udp    = $prt2obj->{'udp 1 65535'};

    # Declare chain names.
    for my $chain (@$chains) {
        my $name = $chain->{name};
        print ":$name -\n";
    }

    # Define chains.
    for my $chain (@$chains) {
        my $name   = $chain->{name};
        my $prefix = "-A $name";

#	my $steps = my $accept = my $deny = 0;
        for my $rule (@{ $chain->{rules} }) {
            my $action = $rule->{action};
            my $action_code =
                ref($action)        ? $action->{name}
              : $action eq 'permit' ? 'ACCEPT'
              :                       'droplog';

            # Calculate maximal number of matches if
            # - some rules matches (accept) or
            # - all rules don't match (deny).
#	    $steps += 1;
#	    if ($action eq 'permit') {
#		$accept = max($accept, $steps);
#	    }
#	    elsif ($action eq 'deny') {
#		$deny = max($deny, $steps);
#	    }
#	    elsif ($rule->{goto}) {
#		$accept = max($accept, $steps + $action->{a});
#	    }
#	    else {
#		$accept = max($accept, $steps + $action->{a});
#		$steps += $action->{d};
#	    }

            my $jump = $rule->{goto} ? '-g' : '-j';
            my $result = "$jump $action_code";
            if (my $src = $rule->{src}) {
                if ($src->{mask} ne $zero_ip) {
                    $result .= ' -s ' . prefix_code($src);
                }
            }
            if (my $dst = $rule->{dst}) {
                if ($dst->{mask} ne $zero_ip) {
                    $result .= ' -d ' . prefix_code($dst);
                }
            }
          ADD_PROTO:
            {
                my $src_range = $rule->{src_range};
                my $prt       = $rule->{prt};
                last ADD_PROTO if not $src_range and not $prt;
                last ADD_PROTO if $prt and $prt->{proto} eq 'ip';
                if (not $prt) {
                    last ADD_PROTO if $src_range->{proto} eq 'ip';
                    $prt =
                        $src_range->{proto} eq 'tcp'  ? $prt_tcp
                      : $src_range->{proto} eq 'udp'  ? $prt_udp
                      : $src_range->{proto} eq 'icmp' ? $prt_icmp
                      :                                 $prt_ip;
                }

#               debug("c ",print_rule $rule) if not $src_range or not $prt;
                $result .= ' ' . iptables_prt_code($src_range, $prt);
            }
            print "$prefix $result\n";
        }

#	$deny = max($deny, $steps);
#	$chain->{a} = $accept;
#	$chain->{d} = $deny;
#	print "# Max tests: Accept: $accept, Deny: $deny\n";
    }

    # Empty line as delimiter.
    print "\n";
    return;
}

sub iptables_acl_line {
    my ($rule, $prefix) = @_;
    my ($action, $src, $dst, $src_range, $prt) =
      @{$rule}{qw(action src dst src_range prt)};
    my $action_code =
        ref($action)        ? $action->{name}
      : $action eq 'permit' ? 'ACCEPT'
      :                       'droplog';
    my $jump = $rule->{goto} ? '-g' : '-j';
    my $result = "$prefix $jump $action_code";
    if ($src->{mask} ne $zero_ip) {
        $result .= ' -s ' . prefix_code($src);
    }
    if ($dst->{mask} ne $zero_ip) {
        $result .= ' -d ' . prefix_code($dst);
    }
    if ($prt->{proto} ne 'ip') {
        $result .= ' ' . iptables_prt_code($src_range, $prt);
    }
    print "$result\n";
    return;
}

sub print_iptables_acl {
    my ($acl_info) = @_;
    my $name = $acl_info->{name};
    print ":$name -\n";
    my $rules = $acl_info->{rules};
    my $intf_prefix = "-A $name";
    for my $rule (@$rules) {
        iptables_acl_line($rule, $intf_prefix);
    }
}
*/

type Expanded_Rule struct {
	deny bool
	src, dst *IP_Net
	prt, src_range	*Proto
	log string
}

type ACL_Info struct {
	name string
	is_std_acl bool
//	prt2obj
	intf_rules, rules []*Expanded_Rule
	ip_net2obj Name2IP_Net
	filter_only, opt_networks, no_opt_addrs []*IP_Net
	network_00 *IP_Net
}

func convert_rule_objects (rules []*jRule, ip_net2obj Name2IP_Net) []*Expanded_Rule {
	if rules == nil { return nil }
	var expanded []*Expanded_Rule
	for _, rule := range rules {
		src_list := ip_net_list(rule.src, ip_net2obj)
		dst_list := ip_net_list(rule.dst, ip_net2obj)
		// prt_list := prt_list(rule.prt, prt2obj)
		// src_range := prt(rule.src_range, prt2obj)
		for _, src := range src_list {
			for _, dst := range dst_list {
				expanded =
					append(
					expanded, &Expanded_Rule{ deny: rule.deny, src: src, dst: dst, })
			}
		}
	}
	return expanded
}
	
type Router_Data struct {
	model string
	acls []*ACL_Info
	log_deny string
//	filter_only []string
//	do_objectgroup bool
}

func ip_net_list (names []string, ip_net2obj Name2IP_Net) ([]*IP_Net) {
	if names == nil {
		return nil
	}
	result := make([]*IP_Net, 0, len(names))
	for i, name := range names {
		obj, ok := ip_net2obj[name];
		if !ok {
			obj = create_ip_obj(name)
			ip_net2obj[name] = obj
		}
		result[i] = obj
	}
	return result
}

//go:generate easyjson Pass2.go
//easyjson:json
type jRouter_Data struct {
	model string
	acls []jACL_Info
	filter_only []string
	do_objectgroup bool
}
type jACL_Info struct {
	name string
	is_std_acl bool
	intf_rules, rules []*jRule
	opt_networks, no_opt_addrs, need_protect []string
	is_crypto_acl bool
	add_permit bool
}
type jRule struct {
	deny bool
	src, dst, prt []string
	src_range string
}

func prepare_acls (path string) Router_Data {
	var jdata jRouter_Data
	fd, err := ioutil.ReadFile(path)
	if err != nil { panic(err) }
	err = easyjson.Unmarshal(fd, &jdata)
	if err != nil { panic(err) }
	model := jdata.model
	do_objectgroup := jdata.do_objectgroup
	raw_acls := jdata.acls
	acls := make([]*ACL_Info, len(raw_acls))
	for i, raw_info := range raw_acls {
		
		// Process networks and protocols of each interface individually,
		// because relation between networks may be changed by NAT.
		ip_net2obj := make(Name2IP_Net)
		// my $prt2obj    = $acl_info->{prt2obj}    = {};

		intf_rules := convert_rule_objects(raw_info.intf_rules, ip_net2obj)
		rules := convert_rule_objects(raw_info.rules, ip_net2obj)

		filter_only := ip_net_list(jdata.filter_only, ip_net2obj)
		
		opt_networks := ip_net_list(raw_info.opt_networks, ip_net2obj)
		for _, obj := range opt_networks {
			obj.opt_networks = true
		}
		no_opt_addrs := ip_net_list(raw_info.no_opt_addrs, ip_net2obj)
		for _, obj := range no_opt_addrs {
			obj.no_opt_addrs = true
		}
		need_protect := ip_net_list(raw_info.need_protect, ip_net2obj)
		for _, obj := range need_protect {
			obj.need_protect = true
		}
		setup_ip_net_relation(ip_net2obj)

		acl_info := ACL_Info{
			raw_info.name,
			raw_info.is_std_acl,
			intf_rules, rules,
			ip_net2obj,
			filter_only, opt_networks, no_opt_addrs,
			ip_net2obj["0.0.0.0/0"],
		}
		acls[i] = &acl_info
    
		if need_protect != nil {
			mark_supernets_of_need_protect(need_protect)
		}
		if model == "Linux" {
//            add_tcp_udp_icmp(prt2obj);
		}
        
//        setup_prt_relation($prt2obj);
//        $acl_info->{prt_ip} = $prt2obj->{ip};
        
		if model == "Linux" {
//			find_chains(acl_info, router_data);
		} else {
//			intf_rules = optimize_rules(intf_rules, acl_info)
//			intf_rules = join_ranges(intf_rules, prt2obj)
//			rules = optimize_rules(rules, acl_info)
//			rules = join_ranges(rules, prt2obj)
//			intf_rules = move_rules_esp_ah(intf_rules, prt2obj)
//			rules = move_rules_esp_ah(rules, prt2obj)

			has_final_permit := true //check_final_permit(rules);
			add_permit       := raw_info.add_permit
//			add_protect_rules(acl_info, has_final_permit || add_permit)
			if do_objectgroup && !raw_info.is_crypto_acl {
//				find_objectgroups(acl_info, router_data);
			}
			if filter_only != nil && !add_permit {
//				add_local_deny_rules(acl_info, router_data);
			} else if !has_final_permit {
//				add_final_permit_deny_rule(acl_info, router_data);
			}
		}
	}
	return Router_Data{model: model, acls: acls};
}

// Given IP or group object, return its address in Cisco syntax.
func cisco_acl_addr (obj *IP_Net, model string) string {
	ip, mask := obj.net.IP, net.IP(obj.net.Mask)

	// Object group.
	if ip == nil {
		var keyword string
		if model == "NX-OS" {
			keyword = "addrgroup"
		} else {
			keyword = "object-group"
		}
		return keyword + " " + obj.name
	} else if mask.Equal(zero_ip) {
		return "any"
	} else if model == "NX-OS" {
		return obj.name
	} else {
		ip_code := ip.String()
		if mask.Equal(max_ip) {
			return "host " + ip_code
		} else {
			
			// Inverse mask bits.
			if model == "NX-OS" || model == "IOS" {
				for i, byte := range mask {
					mask[i] = ^byte
				}
			}
			mask_code := mask.String()
			return ip_code + " " + mask_code
		}
	}
}

/*
sub print_object_groups {
    my ($groups, $acl_info, $model) = @_;
    my $ip_net2obj = $acl_info->{ip_net2obj};
    my $keyword = $model eq 'NX-OS'
                ? 'object-group ip address'
                : 'object-group network';
    for my $group (@$groups) {

        my $numbered = 10;
        print "$keyword $group->{name}\n";
        for my $element (@{ $group->{elements} }) {

            # Reject network with mask = 0 in group.
            # This occurs if optimization didn't work correctly.
            $zero_ip eq $element->{mask} 
                and fatal_err(
                    "Unexpected network with mask 0 in object-group"
                );
            my $adr = cisco_acl_addr($element, $model);
            if ($model eq 'NX-OS') {
                print " $numbered $adr\n";
                $numbered += 10;
            }
            elsif ($model eq 'ACE') {
                print " $adr\n";
            }
            else {
                print " network-object $adr\n";
            }
        }
    }
}
*/

// Returns 3 values for building a Cisco ACL:
// permit <val1> <src> <val2> <dst> <val3>
func cisco_prt_code (src_range, prt *Proto) (t1, t2, t3 string) {
	proto := prt.proto
	
	if proto == "ip" {
        return "ip", "", ""
	} else if proto == "tcp" || proto == "udp" {
		port_code := func (range_obj *Proto) string {
			ports := range_obj.ports
			v1, v2 := ports[0], ports[1]
			if v1 == v2 {
				return fmt.Sprint("eq ", v1)
			} else if v1 == 1 && v2 == 65535 {
				return ""
			} else if v2 == 65535 {
				return fmt.Sprint("gt ", v1 - 1)
			} else if v1 == 1 {
				return fmt.Sprint("lt ", v2 + 1)
			} else {
				return fmt.Sprint("range ", v1, v2)
			}
		}
		dst_prt := port_code(prt)
		if prt.established {
			if dst_prt != "" {
				dst_prt += " established"
			} else {
				dst_prt = "established"
			}
		}
		var src_prt string
		if src_prt != "" {
			src_prt = port_code(src_range)
		}
		return proto, src_prt, dst_prt
	} else if proto == "icmp" {
		type_ := prt.type_
		if type_ != -1 {
			code := prt.code
			if code != -1 {
				return proto, "", fmt.Sprint(type_, code)
			} else {
				return proto, "", fmt.Sprint(type_)
			}
		} else {
			return proto, "", ""
		}
	} else {
		return proto, "", ""
	}
}

func get_cisco_action (deny bool) string {
	var action string
	if deny {
		action = "deny"
	} else {
		action = "permit"
	}
	return action
}

func print_asa_std_acl (acl_info *ACL_Info, model string) {
	rules := acl_info.rules
	for _, rule := range rules {
		fmt.Println(
			"access-list",
			acl_info.name,
			"standard",
			get_cisco_action(rule.deny),
			cisco_acl_addr(rule.src, model))
	}
}

func print_cisco_acl (acl_info *ACL_Info, router_data Router_Data) {
	model := router_data.model

	if acl_info.is_std_acl {
		print_asa_std_acl(acl_info, model)
		return
	}

	intf_rules := acl_info.intf_rules
	rules := acl_info.rules
	name := acl_info.name
	numbered := int(10)
	var prefix string
	if model == "IOS" {
		fmt.Println("ip access-list extended", name)
	} else if model == "NX-OS" {
		fmt.Println("ip access-list", name)
	} else if model == "ASA" || model == "ACE" {
		prefix = "access-list " + name + " extended"
	}

	for _, rules := range [][]*Expanded_Rule{intf_rules, rules} {
		for _, rule := range rules {
			action := get_cisco_action(rule.deny)
			proto_code, src_port_code, dst_port_code :=
			  cisco_prt_code(rule.src_range, rule.prt)
			result := fmt.Sprintln(prefix, action, proto_code)
			result += " " + cisco_acl_addr(rule.src, model)
			if src_port_code != "" {
				result += " " + src_port_code
			}
			result += " " + cisco_acl_addr(rule.dst, model)
			if dst_port_code != "" {
				result += " " + dst_port_code
			}

			if rule.log != "" {
            result += " " + rule.log
			} else if rule.deny && router_data.log_deny != "" {
            result += " " + router_data.log_deny
			}

			// Add line numbers.
			if model == "NX-OS" {
				result = fmt.Sprintf(" %d%s", numbered, result)
            numbered += 10
			}
			fmt.Println(result)
		}
	}
}

func print_acl (acl_info *ACL_Info, router_data Router_Data) {
	model := router_data.model

	if model == "Linux" {

		// Print all sub-chains at once before first toplevel chain is printed.
		/*
		if router_data.chains != nil {
			print_chains(router_data)
			router_data.chains = nil
		}
		print_iptables_acl(acl_info)
      */
	} else {
		/*
		if groups := acl_info.object_groups; groups != nil {
			print_object_groups(groups, acl_info, model)
		}
      */   
		print_cisco_acl(acl_info, router_data)
	}
}

func print_combined (config []string, router_data Router_Data, out_path string) {

	// Redirect print statements to out_path.
	out_fd, err := os.Create(out_path)
	if err != nil {
		fatal_err("Can't open %s for writing: %v", out_path, err)
	}
	old := os.Stdout
	defer func () { os.Stdout = old }()

	acl_hash := make(map[string]*ACL_Info)
	for _, acl := range router_data.acls {
		acl_hash[acl.name] = acl
	}

	// Print config and insert printed ACLs at "#insert <name>" markers.
	re := regexp.MustCompile("^#insert (.*)\n$")
	for _, line := range config {

		indexes := re.FindStringSubmatchIndex(line)

		if indexes != nil {
			// Print ACL.
			name := line[indexes[2] : indexes[3]]
			acl_info, found := acl_hash[name]
			if !found { fatal_err("Unexpected ACL %s", name) }
			print_acl(acl_info, router_data);
		} else {
			// Print unchanged config line.
			fmt.Println(line)
		}
    }   

	if err := out_fd.Close(); err != nil {
		fatal_err("Can't close %s: %v", out_path, err)
	}
}

func isDir (path string) bool {
	stat, err := os.Stat(path) 
	return err == nil && stat.Mode().IsDir()
}

func isRegular (path string) bool {
	stat, err := os.Stat(path) 
	return err == nil && stat.Mode().IsRegular()
}

// Try to use pass2 file from previous run.
// If identical files with extension .config and .rules
// exist in directory .prev/, then use copy.
func try_prev (device_name, dir, prev string) bool {
	if !isDir(prev) {
		return false
	}
	prev_file := prev + "/" + device_name
	if !isRegular(prev_file) {
		return false
	}
	code_file := dir + "/" + device_name
	for _, ext := range [...]string{"config", "rules"} {
		pass1name := code_file + "." + ext
		pass1prev := prev_file + "." + ext
      if !isRegular(pass1prev) { return false }
		cmd := exec.Command("cmp", "-s", pass1name, pass1prev)
		if cmd.Run() != nil { return false }
	}
	cmd := exec.Command("cp", "-p", prev_file, code_file)
	if cmd.Run() != nil { return false }

	// File was found and copied successfully.
	diag_msg("Reused .prev/" + device_name)
	return true
}

func read_file_lines (filename string) []string {
	fd, err := os.Open(filename)
	if err != nil {
		fatal_err("Can't open %s for reading: %v", filename, err)
	}
	result := make([]string, 0)
	scanner := bufio.NewScanner(fd)
	for scanner.Scan() {
		line := scanner.Text()
		result = append(result, line)
	}
	if err := scanner.Err(); err != nil {
		fatal_err("While reading device names: %v", err)
	}
	return result
}

func pass2_file (device_name, dir string, c chan bool) {
	success := false

	// Send ok on success
	defer func () { c <- success }()

	file := dir + "/" + device_name
	router_data := prepare_acls(file + ".rules")
	config := read_file_lines(file + ".config")
	print_combined(config, router_data, file)
	success = true
}

func apply_concurrent (device_names_fh *os.File, dir, prev string) {

	var generated, reused, errors int;
	concurrent := config.concurrent
	c := make(chan bool, concurrent)
	workers_left := concurrent

	wait_and_check := func () {
		if <-c {
			generated++;
		} else {
			errors++
		}
	}
		
	// Read to be processed files line by line.
	scanner := bufio.NewScanner(device_names_fh)
	for scanner.Scan() {
		device_name := scanner.Text()

		if try_prev(device_name, dir, prev) {
			reused++
		} else if (0 < workers_left) {
			// Start concurrent jobs at beginning.
			go pass2_file(device_name, dir, c)
			workers_left--
		} else {
			// Start next job, after some job has finished.
			wait_and_check()
			go pass2_file(device_name, dir, c)
		}
	}
	
	// Wait for all jobs to be finished.
	for 0 < len(c) {
		wait_and_check()
	}

	if err := scanner.Err(); err != nil {
		fatal_err("While reading device names: %v", err)
	}

	if errors > 0 {
		fatal_err("Failed")
	}
	if generated > 0 {
		info("Generated files for %d devices", generated);
	}
	if reused > 0 {
		info("Reused %d files from previous run", reused);
	}
}


func pass2 (dir string) {
	prev := dir + "/.prev"

	// Read to be processed files either from STDIN or from file.
	var from_pass1 *os.File
	if config.pipe {
		from_pass1 = os.Stdin
	} else {
		devlist := dir + "/.devlist"
		var err error
		from_pass1, err = os.Open(devlist)
		if err != nil {
			fatal_err("Can't open %s for reading: %v", devlist, err)
		}
	}
	
	apply_concurrent(from_pass1, dir, prev);
	
	// Remove directory '.prev' created by pass1
	// or remove symlink '.prev' created by newpolicy.pl.
	err := os.RemoveAll(prev)
	if err != nil {
		fatal_err("Can't remove %s: %v", prev, err)
	}
}

func main() {
	if (len(os.Args) != 2) {
		fatal_err("Usage: %s DIR", os.Args[0]);
	}
	var dir = os.Args[1]
	pass2(dir)
}
