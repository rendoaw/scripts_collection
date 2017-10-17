#!/usr/bin/env python

import sys
import re
import json
import os
import argparse
import copy
import traceback
from netaddr import IPAddress,IPNetwork
import pexpect

nodeInfoTemplate = {}
nodeInfoTemplate['id'] = ''
nodeInfoTemplate['index'] = ''
nodeInfoTemplate['data'] = {}
nodeInfoTemplate['data']['hostname'] = ''
nodeInfoTemplate['data']['area'] = ''
nodeInfoTemplate['data']['ipAddress'] = ''


linkInfoTemplate = {}
linkInfoTemplate['id'] = 0
linkInfoTemplate['name'] = 0
linkInfoTemplate['source'] = 0
linkInfoTemplate['target'] = 0
linkInfoTemplate['data'] = {}
linkInfoTemplate['data']['name'] = 0
linkInfoTemplate['data']['ospfMetricA'] = ''
linkInfoTemplate['data']['ospfMetricZ'] = ''
linkInfoTemplate['data']['ipA'] = ''
linkInfoTemplate['data']['ipZ'] = ''
linkInfoTemplate['data']['area'] = ''
linkInfoTemplate['data']['subnet'] = ''
linkInfoTemplate['data']['hostnameA'] = ''
linkInfoTemplate['data']['hostnameZ'] = ''
linkInfoTemplate['data']['ospfArea'] = ''


def arguments_parser():
    parser = argparse.ArgumentParser(description="Options:")
    parser.add_argument('--h', help='target host or IP' )
    parser.add_argument('--u', help='username', nargs='?', const=1, default="" )
    parser.add_argument('--p', help='password', nargs='?', const=1, default="" )
    parser.add_argument('--os', help='operating system', nargs='?', const=1, default="ios" )
    parser.add_argument('--quiet', action='store_true', help='hide cli output')
    parser.add_argument('--graphfile', help='Graph Output file' )
    parser.add_argument('--ospffile', help='Raw OSPF database file' )
    parser.set_defaults(detail=False)
    args = parser.parse_args()
    return args

def jsonpretty(text):
    return json.dumps(text, indent=4, sort_keys=True)


def read_file(filename):
    cmds = ""
    if filename is not '':
        finput = open(filename)
        lines = [x.replace('\n', '') for x in finput]
        finput.close()
    return lines


def write_json_file(filename, j):
    f = open(filename, 'w')
    json.dump(j, f, sort_keys=True, indent=4)
    return


def collect_data(cmds):

    try:
        child = pexpect.spawn('ssh %s@%s' % (args.u, args.h))
        if not args.quiet:
            child.logfile = sys.stdout
        child.timeout = 5
        child.expect('assword:')
    except pexpect.TIMEOUT:
        raise OurException("Couldn't log on to the device")

    outputs = []
    child.sendline(args.p)
    child.expect(['>', '#'])
    parse = cmds.split(';')
    for cmd in parse:
        child.sendline(cmd)
        child.expect(['>', '#'])
        outputs.append(child.before)
    child.sendline('exit')
    return outputs


def read_ospf_cisco(lines):
    ospfdb = {}

    lsa_type = ""
    link_type = ""
    lsa_id = ""
    for line in lines:
        parse = re.split('\s+', line)

        if "Router Link States" in line:
            lsa_type = "router"
            area = parse[5].replace(')','')
            link_type = ""
            if area not in ospfdb:
                ospfdb[area] = {}
                ospfdb[area]['routers'] = {}
                ospfdb[area]['networks'] = {}
                ospfdb[area]['opaque'] = {}
            continue

        if lsa_type == "router" and "Link State ID:" in line:
            lsa_id = parse[4].replace('*','')
            if lsa_id not in ospfdb[area]['routers']:
                ospfdb[area]['routers'][lsa_id] = {}
            ospfdb[area]['routers'][lsa_id]["lsa_id"] = lsa_id
            ospfdb[area]['routers'][lsa_id]["interfaces"] = {}
            continue

        if lsa_type == "router" and "Advertising Router:" in line:
            adv_id = parse[3].replace('*', '')
            ospfdb[area]['routers'][lsa_id]["advertising_router"] = adv_id
            continue

        if lsa_type == "router" and "point-to-point" in line:
            link_type = "p2p"
            remote_id = ""
            continue

        if lsa_type == "router" and link_type == "p2p" and "Neighboring Router ID:" in line:
            remote_id = parse[6]
            continue

        if lsa_type == "router" and link_type == "p2p" and "Router Interface address:" in line:
            local_intf_ip = parse[6]
            ospfdb[area]['routers'][lsa_id]["interfaces"][local_intf_ip] = {}
            ospfdb[area]['routers'][lsa_id]["interfaces"][local_intf_ip]["local_ip"] = local_intf_ip
            ospfdb[area]['routers'][lsa_id]["interfaces"][local_intf_ip]["remote_id"] = remote_id
            ospfdb[area]['routers'][lsa_id]["interfaces"][local_intf_ip]["interface_type"] = "p2p"
            continue

        if lsa_type == "router" and link_type == "p2p" and ( " Metrics:" in line or "Metric:" in line ):
            ospfdb[area]['routers'][lsa_id]["interfaces"][local_intf_ip]["metric"] = parse[4]
            continue

        if lsa_type == "router" and "a Stub Network" in line:
            link_type = "stub"
            pass

        if lsa_type == "router" and "a Transit Network" in line:
            link_type = "transit"
            continue

        if lsa_type == "router" and link_type == "transit" and "Designated Router address:" in line:
            dr_ip = parse[6]
            continue

        if lsa_type == "router" and link_type == "transit" and "Router Interface address:" in line:
            local_intf_ip = parse[6]
            ospfdb[area]['routers'][lsa_id]["interfaces"][local_intf_ip] = {}
            ospfdb[area]['routers'][lsa_id]["interfaces"][local_intf_ip]["dr_ip"] = dr_ip
            ospfdb[area]['routers'][lsa_id]["interfaces"][local_intf_ip]["local_ip"] = local_intf_ip
            ospfdb[area]['routers'][lsa_id]["interfaces"][local_intf_ip]["interface_type"] = "transit"
            ospfdb[area]['routers'][lsa_id]["interfaces"][local_intf_ip]["metric"] = ""
            continue

        if lsa_type == "router" and link_type == "transit" and " Metric:" in line:
            ospfdb[area]['routers'][lsa_id]["interfaces"][local_intf_ip]["metric"] = parse[4]
            continue

        if "Network Link States " in line or "Net Link States " in line:
            lsa_type = "networks"
            continue

        if lsa_type == "networks" and "Link State ID:" in line:
            link_type = "transit"
            lsa_id = parse[4].replace('*', '')
            ospfdb[area]['networks'][lsa_id] = {}
            ospfdb[area]['networks'][lsa_id]["lsa_id"] = lsa_id
            ospfdb[area]['networks'][lsa_id]["advertising_router"] = ""
            ospfdb[area]['networks'][lsa_id]["members"] = {}
            continue

        if lsa_type == "networks" and "Advertising Router:" in line:
            adv_id = parse[3].replace('*', '')
            ospfdb[area]['networks'][lsa_id]["advertising_router"] = adv_id
            continue

        if lsa_type == "networks" and "Network Mask:" in line:
            netmask = parse[3].replace('/','')
            cidr = "10.10.0.0/"+netmask
            try:
                ospfdb[area][lsa_type][lsa_id]["netmask"] = str(IPNetwork(cidr).netmask)
            except:
                print "error: netmask = "+netmask
                traceback.print_exc()
                sys.exit(9999)
            continue

        if lsa_type == "networks" and "Attached Router: " in line:
            ospfdb[area]['networks'][lsa_id]["members"][parse[3]] = 1
            continue


    for area in ospfdb:
        for lsa in ospfdb[area]["routers"]:
            for intf in ospfdb[area]["routers"][lsa]["interfaces"]:
                entry = ospfdb[area]["routers"][lsa]["interfaces"][intf]
                if entry["interface_type"] == "transit":
                    entry["netmask"] = ospfdb[area]['networks'][entry['dr_ip']]['netmask']

    return ospfdb



def read_ospf_hp(lines):
    ospfdb = {}
    lsa_type = ""
    link_type = ""
    lsa_id = ""
    for line in lines:
        parse = re.split('\s+', line)

        if "Area: " in line:
            area = parse[2]

        if "Type      : Router" in line:
            lsa_type = "router"
            link_type = ""
            if area not in ospfdb:
                ospfdb[area] = {}
                ospfdb[area]['routers'] = {}
                ospfdb[area]['networks'] = {}
                ospfdb[area]['opaque'] = {}
            continue

        if lsa_type == "router" and "LS ID " in line:
            lsa_id = parse[4].replace('*','')
            if lsa_id not in ospfdb[area]['routers']:
                ospfdb[area]['routers'][lsa_id] = {}
            ospfdb[area]['routers'][lsa_id]["lsa_id"] = lsa_id
            ospfdb[area]['routers'][lsa_id]["interfaces"] = {}
            continue

        if lsa_type == "router" and "Adv Rtr " in line:
            adv_id = parse[4].replace('*', '')
            ospfdb[area]['routers'][lsa_id]["advertising_router"] = adv_id
            continue

        if lsa_type == "router" and "Link ID: " in line:
            link_id = parse[3]
            continue

        if lsa_type == "router" and "Data " in line:
            link_data = parse[3]
            continue

        if lsa_type == "router" and "Link Type: StubNet" in line:
            link_type = "stub"
            continue

        if lsa_type == "router" and "Link Type: TransNet" in line:
            link_type = "transit"
            local_intf_ip = link_data
            ospfdb[area]['routers'][lsa_id]["interfaces"][local_intf_ip] = {}
            ospfdb[area]['routers'][lsa_id]["interfaces"][local_intf_ip]["dr_ip"] = link_id
            ospfdb[area]['routers'][lsa_id]["interfaces"][local_intf_ip]["local_ip"] = link_data
            ospfdb[area]['routers'][lsa_id]["interfaces"][local_intf_ip]["interface_type"] = "transit"
            ospfdb[area]['routers'][lsa_id]["interfaces"][local_intf_ip]["metric"] = ""
            continue

        if lsa_type == "router" and "Link Type: P-2-P" in line:
            link_type = "p2p"
            local_intf_ip = link_data
            ospfdb[area]['routers'][lsa_id]["interfaces"][local_intf_ip] = {}
            ospfdb[area]['routers'][lsa_id]["interfaces"][local_intf_ip]["local_ip"] = local_intf_ip
            ospfdb[area]['routers'][lsa_id]["interfaces"][local_intf_ip]["remote_id"] = link_id
            ospfdb[area]['routers'][lsa_id]["interfaces"][local_intf_ip]["interface_type"] = "p2p"
            continue

        if lsa_type == "router" and "Metric :" in line:
            if link_type == "p2p" or link_type == "transit":
                ospfdb[area]['routers'][lsa_id]["interfaces"][local_intf_ip]["metric"] = ""
                metric = parse[3]
            continue


        if "Type      : Network" in line:
            lsa_type = "networks"
            continue

        if lsa_type == "networks" and "LS ID " in line:
            link_type = "transit"
            lsa_id = parse[4].replace('*', '')
            ospfdb[area]['networks'][lsa_id] = {}
            ospfdb[area]['networks'][lsa_id]["lsa_id"] = lsa_id
            ospfdb[area]['networks'][lsa_id]["advertising_router"] = ""
            ospfdb[area]['networks'][lsa_id]["members"] = {}
            continue

        if lsa_type == "networks" and "Adv Rtr " in line:
            adv_id = parse[4].replace('*', '')
            ospfdb[area]['networks'][lsa_id]["advertising_router"] = adv_id
            continue

        if lsa_type == "networks" and "Net Mask " in line:
            ospfdb[area][lsa_type][lsa_id]["netmask"] = parse[4]
            continue

        if lsa_type == "networks" and "Attached Router " in line:
            ospfdb[area]['networks'][lsa_id]["members"][parse[3]] = 1
            continue


    for area in ospfdb:
        for lsa in ospfdb[area]["routers"]:
            for intf in ospfdb[area]["routers"][lsa]["interfaces"]:
                entry = ospfdb[area]["routers"][lsa]["interfaces"][intf]
                if entry["interface_type"] == "transit":
                    entry["netmask"] = ospfdb[area]['networks'][entry['dr_ip']]['netmask']

    return ospfdb




def read_ospf_juniper(lines):
    ospfdb = {}
    lsa_type = ""
    link_type = ""
    lsa_id = ""
    for line in lines:
        parse = re.split('\s+', line)

        if " OSPF database, Area" in line:
            area = parse[4]
            if area not in ospfdb:
                ospfdb[area] = {}
                ospfdb[area]['routers'] = {}
                ospfdb[area]['networks'] = {}
                ospfdb[area]['opaque'] = {}
            continue

        if line.startswith("Area"):
            area = parse[1]
            if area not in ospfdb:
                ospfdb[area] = {}
                ospfdb[area]['routers'] = {}
                ospfdb[area]['networks'] = {}
                ospfdb[area]['opaque'] = {}
            continue

        if line.startswith("Router  "):
            lsa_type = "router"
            link_type = ""
            lsa_id = parse[1].replace('*', '')
            adv_id = parse[2].replace('*', '')
            if lsa_id not in ospfdb[area]['routers']:
                ospfdb[area]['routers'][lsa_id] = {}
            ospfdb[area]['routers'][lsa_id]["lsa_id"] = lsa_id
            ospfdb[area]['routers'][lsa_id]["interfaces"] = {}
            ospfdb[area]['routers'][lsa_id]["advertising_router"] = adv_id
            continue

        if lsa_type == "router" and "Type PointToPoint" in line:
            link_type = "p2p"
            local_intf_ip = parse[4].replace(',','')
            ospfdb[area]['routers'][lsa_id]["interfaces"][local_intf_ip] = {}
            ospfdb[area]['routers'][lsa_id]["interfaces"][local_intf_ip]["local_ip"] = local_intf_ip
            ospfdb[area]['routers'][lsa_id]["interfaces"][local_intf_ip]["remote_id"] = parse[2].replace(',','')
            ospfdb[area]['routers'][lsa_id]["interfaces"][local_intf_ip]["interface_type"] = "p2p"
            continue

        if lsa_type == "router" and "Type Stub" in line:
            link_type = "stub"
            pass
            #local_intf_ip = parse[2].replace(',','')
            #ospfdb[area]['routers'][lsa_id]["interfaces"][local_intf_ip] = {}
            #ospfdb[area]['routers'][lsa_id]["interfaces"][local_intf_ip]["local_ip"] = local_intf_ip
            #ospfdb[area]['routers'][lsa_id]["interfaces"][local_intf_ip]["netmask"] = parse[4].replace(',','')
            #ospfdb[area]['routers'][lsa_id]["interfaces"][local_intf_ip]["interface_type"] = "stub"

        if lsa_type == "router" and "Type Transit" in line:
            link_type = "transit"
            local_intf_ip = parse[4].replace(',','')
            ospfdb[area]['routers'][lsa_id]["interfaces"][local_intf_ip] = {}
            ospfdb[area]['routers'][lsa_id]["interfaces"][local_intf_ip]["dr_ip"] = parse[2].replace(',','')
            ospfdb[area]['routers'][lsa_id]["interfaces"][local_intf_ip]["local_ip"] = local_intf_ip
            ospfdb[area]['routers'][lsa_id]["interfaces"][local_intf_ip]["interface_type"] = "transit"
            continue

        if lsa_type == "router" and "Default metric" in line:
            if link_type == "p2p" or link_type == "transit":
                ospfdb[area]['routers'][lsa_id]["interfaces"][local_intf_ip]["metric"] = parse[6]
            continue

        if line.startswith("Network "):
            lsa_type = "networks"
            link_type = ""
            lsa_id = parse[1].replace('*', '')
            adv_id = parse[2].replace('*', '')
            ospfdb[area]['networks'][lsa_id] = {}
            ospfdb[area]['networks'][lsa_id]["lsa_id"] = lsa_id
            ospfdb[area]['networks'][lsa_id]["advertising_router"] = adv_id
            ospfdb[area]['networks'][lsa_id]["members"] = {}
            continue

        if lsa_type == "networks" and parse[1] == "mask":
            ospfdb[area][lsa_type][lsa_id]["netmask"] = parse[2]
            continue

        if lsa_type == "networks" and "attached router" in line:
            ospfdb[area]['networks'][lsa_id]["members"][parse[3]] = 1
            continue

    #print jsonpretty(ospfdb)

    for area in ospfdb:
        for lsa in ospfdb[area]["routers"]:
            for intf in ospfdb[area]["routers"][lsa]["interfaces"]:
                entry = ospfdb[area]["routers"][lsa]["interfaces"][intf]
                if entry["interface_type"] == "transit":
                    entry["netmask"] = ospfdb[area]['networks'][entry['dr_ip']]['netmask']

    return ospfdb


def populate_gnode(gnode, hostname="", area="", ipaddr=""):
    gnode['id'] = hostname
    gnode['data']['hostname'] = hostname
    gnode['data']['area'] = area
    gnode['data']['ipAddress'] = ipaddr
    return


def populate_glink(gnodes, glink, node1_idx=0, node2_idx=0, ip1='', ip2='', metric1='', metric2='', area='', is_update_reverse=False):
    node1 = gnodes[node1_idx]['data']
    node2 = gnodes[node2_idx]['data']

    glink['id'] = str(node1_idx)+"_"+str(node2_idx)+'_'+ip1
    glink['source'] = node1_idx
    glink['target'] = node2_idx
    glink['data']['source'] = node1_idx
    glink['data']['target'] = node2_idx
    glink['data']['hostnameA'] = node1['hostname']
    glink['data']['hostnameZ'] = node2['hostname']
    glink['data']['ipA'] = ip1
    glink['data']['ipZ'] = ip2
    glink['data']['ospfMetricA'] = metric1
    glink['data']['ospfMetricZ'] = metric2
    glink['data']['area'] = area
    return



def get_node_id(listname, hostname):
    for n, item in enumerate(listname):
        if item['id'] == hostname:
            return n
    return -1


def get_link_id(listname, node1_index, node2_index):
    for n, item in enumerate(listname):
        if item['source'] == node1_index and item['target'] == node2_index:
            return n
        if item['source'] == node2_index and item['target'] == node1_index:
            return n
    return -1


def populate_graph_from_ospf(ospfdb):
    gnodes = []
    glinks = []
    ip_to_host = {}
    host_to_ip = {}
    #ip_to_host, host_to_ip = read_etc_hosts(HOSTFILE)

    for area in ospfdb:
        # first pass - collect all router-id
        for router_id in ospfdb[area]['routers']:
            node1_idx = get_node_id(gnodes, router_id)
            if node1_idx == -1:
                nodeInfo = copy.deepcopy(nodeInfoTemplate)
                populate_gnode(nodeInfo, hostname=router_id, area=area, ipaddr=router_id)
                gnodes.append(nodeInfo)
                node1_idx = get_node_id(gnodes, router_id)

        # first pass - collect all network lsa id
        for network_id in ospfdb[area]['networks']:
            network_data = ospfdb[area]['networks'][network_id]
            node1_idx = get_node_id(gnodes, network_id)
            if node1_idx == -1:
                nodeInfo = copy.deepcopy(nodeInfoTemplate)
                populate_gnode(nodeInfo, hostname="pseudo_"+network_id, area=area, ipaddr=network_id)
                gnodes.append(nodeInfo)
                node1_idx = get_node_id(gnodes, network_id)

        # second pass, stitch p2p link
        for router_id in ospfdb[area]['routers']:
            router_data = ospfdb[area]['routers'][router_id]
            node1_idx = get_node_id(gnodes, router_id)
            for intf in router_data['interfaces']:
                intf_data = router_data['interfaces'][intf]
                if 'linked' in intf_data:
                    continue
                if intf_data['interface_type'] == "p2p":
                    local_ip = intf_data['local_ip']
                    remote_id = intf_data['remote_id']
                    node2_idx = get_node_id(gnodes, remote_id)
                    for intf2 in ospfdb[area]['routers'][remote_id]['interfaces']:
                        intf_data2 = ospfdb[area]['routers'][remote_id]['interfaces'][intf2]
                        if intf_data2["interface_type"] != "p2p":
                            continue
                        if intf_data2['remote_id'] == router_id and not "linked" in intf_data2:
                            remote_ip = intf_data2['local_ip']
                            intf_data['linked'] = True
                            intf_data2['linked'] = True
                            glink = copy.deepcopy(linkInfoTemplate)
                            populate_glink(gnodes, glink, node1_idx, node2_idx, ip1=local_ip,
                                    ip2=remote_ip,
                                    metric1=intf_data['metric'],
                                    metric2=intf_data2['metric'],
                                    area=area)
                            glinks.append(glink)
                            continue
                if intf_data['interface_type'] == "transit":
                    local_ip = intf_data['local_ip']
                    dr_ip = intf_data['dr_ip']
                    node2_idx = get_node_id(gnodes, "pseudo_"+dr_ip)
                    glink = copy.deepcopy(linkInfoTemplate)
                    populate_glink(gnodes, glink, node1_idx, node2_idx, ip1=local_ip, ip2='', metric1=intf_data['metric'], metric2='0', area=area)
                    glinks.append(glink)


    json_data = {'nodes':gnodes, 'links':glinks}
    #write_json_file('result/node_data.json',node_data)
    return json_data



if __name__ == "__main__":
    args = arguments_parser()
    graph_file = "ospf_graph.json"
    osType = "junos"
    if args.os:
        osType = args.os

    ospfdb = {}
    if osType == "junos":
        if args.ospffile:
            lines = read_file(args.ospffile)
        else:
            cmds = "show ospf database detail | no-more"
            lines = collect_data(cmds)[0].split("\n")
        ospfdb = read_ospf_juniper(lines)
    elif osType == "ios" or osType == "zte":
        if args.ospffile:
            lines = read_file(args.ospffile)
        else:
            cmds = "terminal length 0;show ip ospf  database detail"
            lines = collect_data(cmds)[0].split("\n")
        ospfdb = read_ospf_cisco(lines)
    elif osType == "hp":
        if args.ospffile:
            lines = read_file(args.ospffile)
        else:
            cmds = "terminal length 0;show ip ospf  database detail"
            lines = collect_data(cmds)[0].split("\n")
        ospfdb = read_ospf_hp(lines)

    print json.dumps(ospfdb, indent=4, sort_keys=True)

    d3_data = populate_graph_from_ospf(ospfdb)
    write_json_file(graph_file, d3_data)

