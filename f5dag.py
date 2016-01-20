#!/usr/bin/env python
# Copyright (C) F5 Networks, Inc. 2015-2016
# Author: Christian Koenning, christian@f5.com
# No part of the software may be reproduced or transmitted in any
# form or by any means, electronic or mechanical, for any purpose,
# without express written permission of F5 Networks, Inc.


import eossdk
import sys
import json
import urllib2
import time
import socket
import hashlib


class Disaggregator():
    ''' encapsulates Disaggration functionality
            connects to url and retrieves JSON doc
            from the TMOS Controller
    '''

    def __init__(self, directFlowMgr, url, logger):
        self.flowsAdded = 0
        self.flowsDeleted = 0
        self._directFlowMgr = directFlowMgr
        self._url = url
        self._rules = ''
        self._logger = logger
        self._monitorVlan = ''
        self._clusterMembers = ''
        self._clusterMacAddr = ''
        self.updateDag()
        self.installedFlows = set()

    def setUrl(self, url):
        ''' setter for external update of _url '''
        self._url = url

    def getMonitorVlan(self):
        ''' access method for _monitorVlan '''
        return int(self._monitorVlan)

    def getClusterMembers(self):
        ''' access method for _clusterMembers'''
        return self._clusterMembers

    def updateDag(self):
        ''' retrieves the Disaggregation JSON doc from TMOS'''

        if (self._url == ''):
            data = self.loadDagFromFile()
        else:
            response = urllib2.urlopen(self._url)
            res = response.read()
            data = json.loads(res)

        self._clusterMembers = data['clusterMembers']
        self._monitorVlan = data['monitorVlan']
        self._rules = data['rules']
        self._clusterMacAddr = self.parseClusterMacAddr()

        return True

    def loadDagFromFile(self):
        '''load the Dissagregation data for testing purposes
            from the testsuite.json file
        '''

        json_data = open('/mnt/flash/testsuite.json')
        data = json.load(json_data)
        return data

    def getClusterMacAddr(self):
        ''' external access'''
        return dict.fromkeys(self._clusterMacAddr)

    def parseClusterMacAddr(self):
        ''' parse the dissagregation JSON doc and return all
            virtual mac addresses observed in a set
        '''
        result = set()
        for data in self._rules:
            result.add(data['action']['dl_src'])
        return result

    def calcDottedNetmask(self, mask):
        ''' helper function to cope with CDIR data in the JSON doc
            and directflow expected a dotted netmask
        '''

        bits = 0
        for i in xrange(32-mask, 32):
            bits |= (1 << i)
        return '%d.%d.%d.%d' % ((bits & 0xff000000) >> 24,
                                (bits & 0xff0000) >> 16,
                                (bits & 0xff00) >> 8,
                                (bits & 0xff))

    def createDirectflow(self,
                         forwardingTable,
                         name,
                         ipSrc,
                         ipSrcMask,
                         ipDst,
                         ipDstMask,
                         vlan,
                         ethDst):
        ''' creates directflow entry in the switch. is idempodent'''

        match = eossdk.FlowMatch()
        matchFieldSet = eossdk.FlowMatchFieldSet()
        if vlan is not None:
            matchFieldSet.vlan_id_is(True)
            match.vlan_id_is(int(vlan), 4095)
        if ipSrc is not None:
            matchFieldSet.ip_src_is(True)
            ipSrc = eossdk.IpAddr(ipSrc)
            ipSrcMask = eossdk.IpAddr(ipSrcMask)
            match.ip_src_is(ipSrc, ipSrcMask)
        if ipDst is not None:
            matchFieldSet.ip_dst_is(True)
            ipDst = eossdk.IpAddr(ipDst)
            ipDstMask = eossdk.IpAddr(ipDstMask)
            match.ip_dst_is(ipDst, ipDstMask)
        match.match_field_set_is(matchFieldSet)

        outputInt = eossdk.IntfId(forwardingTable[ethDst])
        outputIntfs = [outputInt]

        action = eossdk.FlowAction()
        actionSet = eossdk.FlowActionSet()
        if outputIntfs is not None:
            actionSet.set_output_intfs_is(True)
            action.output_intfs_is(tuple(outputIntfs))
        if ethDst is not None:
            actionSet.set_eth_dst_is(True)
            newEthDst = eossdk.EthAddr(ethDst)
            action.eth_dst_is(newEthDst)
        action.action_set_is(actionSet)

        self._directFlowMgr.flow_entry_set(eossdk.FlowEntry(name,
                                                            match,
                                                            action,
                                                            0))

    def deleteDirectflow(self, name):
        ''' wrapper function to call Directflow delete from sdk'''
        self._directFlowMgr.flow_entry_del(name)

    def getInstalledFlows(self):
        ''' retrieve all installed flow name and return them in a set'''
        result = set()
        for flow in self._directFlowMgr.flow_entry_iter():
            result.add(flow.name())
        return result

    def updateInstalledFlows(self):
        ''' convinience function to update the installed flows on object'''
        self.installedFlows = self.getInstalledFlows()

    def syncDirectflows(self, forwardingTable, periodic):
        ''' will sync flows from TMOS to Arista
            Note that the uuid is deterministic, and contains
            configTimestamp as prefix,
            vlan, network and netmask as suffix
        '''

        if (periodic):
            self.updateDag()

        self.updateInstalledFlows()

        for rule in self._rules:
            ruleif = forwardingTable[rule['action']['dl_src']]
            name = hashlib.sha1(rule['id'] + ruleif).hexdigest()

            if (name in self.installedFlows):
                self.installedFlows.remove(name)
            else:
                ipSrc = None
                ipSrcMask = None
                ipDst = None
                ipDstMask = None

                if ('nw_src' in rule['match']):
                    srcNet = rule['match']['nw_src']
                    ipSrc, sCdir = srcNet.split('/')
                    ipSrcMask = self.calcDottedNetmask(int(sCdir))
                if ('nw_dst' in rule['match']):
                    dstNet = rule['match']['nw_dst']
                    ipDst, dCdir = dstNet.split('/')
                    ipDstMask = self.calcDottedNetmask(int(dCdir))
                vlan = rule['match']['vlan_vid']
                dstMac = rule['action']['dl_src']
                self.flowsAdded += 1
                self.createDirectflow(forwardingTable,
                                      name,
                                      ipSrc,
                                      ipSrcMask,
                                      ipDst,
                                      ipDstMask,
                                      vlan,
                                      dstMac)

        # whatever is still in the self.installedFlows needs to be deleted
        for flow in self.installedFlows:
            self.flowsDeleted += 1
            self.deleteDirectflow(flow)

        if (self.flowsAdded != 0 or self.flowsDeleted != 0):
            if periodic:
                msg = 'PERIODIC add %s Flows, del %s Flows' % \
                        (self.flowsAdded, self.flowsDeleted)
            else:
                msg = 'FAILOVER updated %s Flows' % self.flowsAdded
            self._logger.log(msg)

        self.flowsAdded = 0
        self.flowsDeleted = 0
        self.installedFlows = None

        return True


class MacHandler(eossdk.AgentHandler,
                 eossdk.MacTableHandler,
                 eossdk.FlowHandler):
    ''' handles the mac address to port mapping
        and registers a callback to the sdk to be notified
        for changes of the virtual mac address of the Honeybee
        Cluster.
    '''

    def __init__(self, sdk):

        self._sdk = sdk
        self.agentMgr = sdk.get_agent_mgr()
        self.macTableMgr = sdk.get_mac_table_mgr()
        self.directFlowMgr = sdk.get_directflow_mgr()

        self.tmosUrl = 'http://10.20.1.10'
        self.syncInterval = 5

        self.logger = Logmsg('f5dag')
        eossdk.FlowHandler.__init__(self, self.directFlowMgr)
        self.dag = Disaggregator(self.directFlowMgr, self.tmosUrl, self.logger)
        self.discoverCluster()
        eossdk.AgentHandler.__init__(self, self.agentMgr)
        eossdk.MacTableHandler.__init__(self, self.macTableMgr)

        self.forwardingTable = dict.fromkeys(self.dag.getClusterMacAddr())

        self.logger.log('initializing F5 TMOS Disaggregator...')

    def getSyncInterval(self):
        ''' convinience function '''
        return self.syncInterval

    def sendDiscoverMessage(self, destIp):
        ''' helper function to send udp messages to
            the cluster members, so that the fwd table will be
            popluated
        '''

        msg = 'sending Discovery Message for %s' % destIp
        self.logger.log(msg)

        self._destIp = destIp
        self._destPort = 666
        self.message = 'F5 discovery'
        self.sock = socket.socket(socket.AF_INET,
                                  socket.SOCK_DGRAM)
        self.sock.sendto(self.message, (self._destIp, self._destPort))

    def discoverCluster(self):
        ''' will send each clusterIpAddresses a discovery
            message
        '''
        for address in self.dag.getClusterMembers():
            self.sendDiscoverMessage(address)

    def queryMacTable(self):
        ''' this function will query the cluster state from the
            forwarding table at startup of the deamon. This is
            important if for any reason the sdk daemon is getting
            restarted unexecptectly
        '''
        foundClusterMacAddresses = 0
        for macKey in self.macTableMgr.mac_table_status_iter():
            macEntry = self.macTableMgr.mac_entry_status(macKey)
            if (macEntry.eth_addr().to_string()
                    in self.forwardingTable and
                    macEntry.vlan_id() == self.dag.getMonitorVlan()):
                        foundClusterMacAddresses += 1
                        self.forwardingTable[macEntry.eth_addr().to_string()]=\
                             macEntry.intf().to_string()
                        msg = 'updating entry for %s ' % (macEntry.to_string())
                        self.logger.log(msg)

        if (foundClusterMacAddresses < len(self.forwardingTable)):
            raise f5ClusterMacAddressesNotFound()

        return True

    def updateControllerStatus(self, status):
        ''' convinience function '''
        if (status == 'connected'):
            status = 'connected on ' + str(time.time())
        self.agentMgr.status_set('Controller', status)
        return True

    def on_initialized(self):
        ''' callback which will be executed after the SDK initalized
            registers the Honeybee cluster virtual mac addresses to the
            on_mac_entry_set callback
        '''

        for fwdTableEntry in self.forwardingTable:
            msg = 'registering mac %s for on_mac_entry_set' % fwdTableEntry
            self.logger.log(msg)

            self.watch_mac_entry(eossdk.MacKey(self.dag.getMonitorVlan(),
                                 eossdk.EthAddr(fwdTableEntry)),
                                 True)

        self.queryMacTable()
        self.agentMgr.status_set('Version', 'Honeybee V1')

        configTmosURL = self.agentMgr.agent_option('tmosUrl')
        if configTmosURL:
            self.tmosUrl = configTmosURL

        configSyncInterval = self.agentMgr.agent_option('syncInterval')
        if configSyncInterval:
            self.syncInterval = configSyncInterval

        self.updateControllerStatus('initializing...')
        if (self.dag.syncDirectflows(self.forwardingTable, True)):
            self.updateControllerStatus('connected')

    def on_agent_option(self, optionName, value):
        ''' callback for Agent option changes'''
        if (value):
            if (optionName == 'tmosUrl'):
                self.tmosUrl = value
                self.dag.setUrl(self.tmosUrl)
            elif(optionName == 'syncInterval'):
                self.syncInterval = value

    def on_mac_entry_set(self, entry):
        ''' callback when the cluster mac address change
            calls the dag to update the flow tables
        '''
        msg = '%s moved to port %s ' % \
            (entry.eth_addr().to_string(),
             entry.intf().to_string())
        self.logger.log(msg)

        self.forwardingTable[entry.eth_addr().to_string()] = \
            entry.intf().to_string()
        self.dag.syncDirectflows(self.forwardingTable, False)

    def on_sync(self):
        ''' sync invoked by the sheduler'''
        # this is the periodic call
        if (self.dag.syncDirectflows(self.forwardingTable, True)):
            self.updateControllerStatus('connected')
        else:
            self.updateControllerStatus('ERROR')


class f5ClusterMacAddressesNotFound(Exception):
    ''' custom defined Exeption which gets
        raised at startup when the cluster node
        port connection cannot be learned from the
        MAC forwarding table. This usually is caused
        by a wiring problem
    '''
    def __str__(self):
        return 'MAC forwarding table does not contain cluster addresses'


class Logmsg(object):
    ''' Wrapper to sent to stdout '''

    def __init__(self, name):
        self.tracer = eossdk.Tracer(name)

    def log(self, msg):
        self.tracer.trace0(msg)
        print msg


class UpdateSheduler(eossdk.TimeoutHandler):
    ''' Sheduler Object from the eossdk '''

    def __init__(self, sdk, macHandler, poll_interval):
        self._sdk = sdk
        self._poll_interval = poll_interval
        self._macHandler = macHandler
        eossdk.TimeoutHandler.__init__(self, self._sdk.get_timeout_mgr())
        self.timeout_time_is(eossdk.now() + self._poll_interval)

    def poll(self):
        self._macHandler.on_sync()

    def on_timeout(self):
        self.poll()
        self.timeout_time_is(eossdk.now() + self._poll_interval)


def main(args):
    ''' Instanciating the Mac Handler and Disaggregator Object'''

    sdk = eossdk.Sdk()
    macHandler = MacHandler(sdk)
    sheduler = UpdateSheduler(sdk, macHandler, macHandler.getSyncInterval())
    sdk.main_loop(sys.argv)

if __name__ == '__main__':
    sys.exit(main(sys.argv))
