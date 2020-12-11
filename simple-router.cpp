/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/***
 * Copyright (c) 2017 Alexander Afanasyev
 *
 * This program is free software: you can redistribute it and/or modify it under the terms of
 * the GNU General Public License as published by the Free Software Foundation, either version
 * 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with this program.
 * If not, see <http://www.gnu.org/licenses/>.
 */

#include "simple-router.hpp"
#include "core/utils.hpp"

#include <fstream>

namespace simple_router {

const std::size_t ETH_SIZE = sizeof(ethernet_hdr);
const std::size_t IP_SIZE = sizeof(ip_hdr);
const std::size_t ARP_SIZE = sizeof(arp_hdr);
int NAT_FLAG = false;
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
// IMPLEMENT THIS METHOD
void
SimpleRouter::handlePacket(const Buffer& packet, const std::string& inIface, int nat_flag)
{


  

  if(nat_flag){
    std::cerr << "Nat Flag" << std::endl;
    NAT_FLAG = true;
    m_natTable.print();
  }

  std::cerr << "Got packet of size " << packet.size() << " on interface " << inIface << std::endl;
  const Interface* iface = findIfaceByName(inIface);

  if (iface != nullptr) {
    std::cerr << getRoutingTable() << std::endl;
    uint16_t ether_Type = ethertype(packet.data());

    const ethernet_hdr *eth_hdr = (ethernet_hdr *) packet.data();
    const Buffer macAddr(std::begin(eth_hdr->ether_dhost), std::end(eth_hdr->ether_dhost)); 
    
    std::string broadcastUpper = "FF:FF:FF:FF:FF:FF";
    std::string broadcastLower = "ff:ff:ff:ff:ff:ff";

std::cout << "ADRRESSES" << std::endl;
  std::cout << macToString(macAddr) << std::endl;
    std::cout << macToString(iface->addr) << std::endl;
    if ( (macToString(macAddr) != broadcastUpper) && (macToString(macAddr) != broadcastLower) && (macToString(macAddr) !=  macToString(iface->addr))) {
      std::cout << macToString(macAddr) << std::endl;
      std::cout << "Packet not for this router" << std::endl;
    }
    else {
      if (ether_Type == ethertype_arp ){
        handleArp(packet,eth_hdr,iface);
      }
      else if (ether_Type == ethertype_ip) {
        handleIp(packet,eth_hdr,iface);
      }
    }
  }

}

void 
SimpleRouter::handleIp(const Buffer& packet, const ethernet_hdr *eth_hdr, const Interface *iface){
 
  std::cout << "IP PACKET " << std::endl;

  const ip_hdr *ipHeader = reinterpret_cast<const ip_hdr *>(packet.data() + ETH_SIZE);

  uint16_t checksum_value = ntohs(cksum((const void *)ipHeader, IP_SIZE));
  if (checksum_value != 0XFFFF || ipHeader->ip_len < IP_SIZE || ipHeader->ip_ttl - 1 <= 0)
  {
    std::cout << "Drop packet. IPV4 validation" << std::endl;
    return; 
  }

  if (ipHeader->ip_p == ip_protocol_icmp && NAT_FLAG )
    {
      std::cout << "ICMP NAT HERE" << std::endl;
     
      handleIcmpNat(ipHeader, packet, eth_hdr, iface); 
      return;
   
      
    }


  if (findIfaceByIp(ipHeader->ip_dst) == nullptr) 
  {   
    std::cout << " LONGEST MATCHING PREFIX " << std::endl;
    RoutingTableEntry routingTableEntry = m_routingTable.lookup(ipHeader->ip_dst);
    std::shared_ptr<ArpEntry> arpEntry = m_arp.lookup(ipHeader->ip_dst);
    const Interface *nextIface = findIfaceByName(routingTableEntry.ifName);
    if (arpEntry != nullptr)
    { //is arp entry
      handleIpv4LongestMatchingPrefix(arpEntry, nextIface, packet);
    }
    else
    {
      handleIpv4SendArp(ipHeader, routingTableEntry, packet, nextIface);
    }                          
  }

  else
  {
    if (ipHeader->ip_p == ip_protocol_icmp)
    {
      std::cout << "ICMP HERE" << std::endl;
   
        handleIcmp(ipHeader, packet, eth_hdr, iface);
      
      
    }
  }


}

void 
SimpleRouter::handleIpv4SendArp(const ip_hdr *ipHdr, RoutingTableEntry routingTableEntry, const Buffer& packet, const Interface *iface){
  std::cout << " IP SEND ARP " << std::endl;
  Buffer request(packet.size());
  memcpy(request.data(), packet.data(), packet.size()); 
  uint8_t *send_ptr = (uint8_t *) request.data();

  ip_hdr *write_ip_hdr = (ip_hdr *)(send_ptr + ETH_SIZE);
  write_ip_hdr->ip_sum = 0;
  write_ip_hdr->ip_sum = cksum((const void *)write_ip_hdr, IP_SIZE);

  std::shared_ptr<ArpRequest> arpRequest = m_arp.queueRequest(ipHdr->ip_dst, request, routingTableEntry.ifName);
  arpRequest->nTimesSent = arpRequest->nTimesSent + 1;
  arpRequest->timeSent = steady_clock::now();
  
  
  Buffer newArpReq(ETH_SIZE + ARP_SIZE);
  uint8_t *responsePtr = (uint8_t *) newArpReq.data();
  ethernet_hdr *write_eth_hdr = (ethernet_hdr *)responsePtr;
  memset(write_eth_hdr->ether_dhost, 255, ETHER_ADDR_LEN);
  memcpy(write_eth_hdr->ether_shost, iface->addr.data(), ETHER_ADDR_LEN);
  write_eth_hdr->ether_type = htons(ethertype_arp);

  arp_hdr *arpHeader = (arp_hdr *)(responsePtr + ETH_SIZE); 
  writeArpHeader(arpHeader, htons(arp_op_request), iface, ipHdr->ip_dst);
  memset(arpHeader->arp_tha, 255, ETHER_ADDR_LEN);
  
  sendPacket(newArpReq, iface->name);
  
  print_hdrs(newArpReq);
}

void 
SimpleRouter::handleIpv4LongestMatchingPrefix(std::shared_ptr<ArpEntry> arpEntry, const Interface *iface, const Buffer& packet){
  std::cout << "  IP HAS ARP ENTRY " << std::endl;
   
  Buffer buffer(packet.size());
  memcpy(buffer.data(), packet.data(), packet.size());

  uint8_t *buffPtr = (uint8_t *)buffer.data();
  ethernet_hdr *ethernetHdr = (ethernet_hdr *)buffPtr; 
  memcpy(ethernetHdr->ether_dhost, arpEntry->mac.data(), ETHER_ADDR_LEN);
  memcpy(ethernetHdr->ether_shost, iface->addr.data(), ETHER_ADDR_LEN); 

  writeIpHeader((ip_hdr *)(buffPtr + ETH_SIZE));

  sendPacket(buffer, iface->name);
  print_hdrs(buffer);
}

void 
SimpleRouter::handleIcmpNat(const ip_hdr *ipHeader, const Buffer& packet, const ethernet_hdr *eth_hdr, const Interface *iface){

    /*RoutingTableEntry routingTableEntry = m_routingTable.lookup(ipHeader->ip_dst);
    std::shared_ptr<ArpEntry> arpEntry = m_arp.lookup(ipHeader->ip_dst);
    const Interface *nextIface = findIfaceByName(routingTableEntry.ifName); 
    
    if( arpEntry == nullptr){
    handleIpv4SendArp(ipHeader, routingTableEntry, packet, nextIface);
    return;
    }else{
      std::cout << "not nullptr reply " << std::endl;
    } */

  std::size_t icmpSize = packet.size() -  ETH_SIZE - IP_SIZE;
  const icmp_hdr *recv_icmp = (icmp_hdr *)(packet.data() + ETH_SIZE + IP_SIZE);
  if( ntohs(cksum((const void *)recv_icmp, icmpSize)) != 0XFFFF){
    std::cout << "bad checksum" << std::endl;
  }
     Buffer buffer(IP_SIZE + ETH_SIZE + icmpSize); 
  memcpy(buffer.data(), packet.data(), packet.size()); 
 uint8_t *bufferPtr = (uint8_t *)buffer.data();

  if (ntohs(cksum((const void *)recv_icmp, icmpSize)) == 0XFFFF && recv_icmp->icmp_type == 0){ 
    // ECHO REPLY (RESPONSE FROM SERVER?)
    // When NAT receives an ICMP echo reply, it must translate back 
    // external address to the original internal address
    // PING responses from the server. In this case, the destination IP address should be
//changed from 172.32.10.1 to 10.0.1.1, so that the client can receive the PING responses
    
    std::cout << "NAT ICMP ECHO REPLY" << std::endl;
    std::cout << "ipHeader->ip_dst" << ipToString(ipHeader->ip_dst) << std::endl;
    std::cout << "ipHeader->ip_src" << ipToString(ipHeader->ip_src) << std::endl;


    ethernet_hdr *write_eth_hdr = (ethernet_hdr *)bufferPtr; 
 // writeEthernetHeader(write_eth_hdr, eth_hdr, iface, htons(ethertype_ip));
   memcpy(write_eth_hdr, eth_hdr, ETH_SIZE );
 //    memcpy(write_eth_hdr->ether_shost, iface->addr.data(), ETHER_ADDR_LEN);                       
  //memcpy(write_eth_hdr->ether_dhost, arpEntry->mac.data(), ETHER_ADDR_LEN); //destination is to send back to source
   
      std::shared_ptr<NatEntry> natEntry = m_natTable.lookup(recv_icmp->icmp_id);

    
    if(natEntry == nullptr){
      std::cout << "ECHO REPLY NAT ENTRY NULLPTR" << std::endl;
    }
    else{
      if(ipHeader -> ip_dst == natEntry -> external_ip){
          std::cout << "ECHO REPLY NAT ENTRY CORRECT ENTRY" << std::endl;
        //SET TIMER??? -- 
      }else{
        std::cout << "ECHO REPLY NAT ENTRY INCORRECT ENTRY" << std::endl;
      }
      
    }


   
      ip_hdr *write_ip_hdr = (ip_hdr *)(bufferPtr + ETH_SIZE);
      write_ip_hdr->ip_tos = ipHeader->ip_tos;
      write_ip_hdr->ip_len = ipHeader->ip_len; 
      write_ip_hdr->ip_id = ipHeader->ip_id;
      write_ip_hdr->ip_off = ipHeader->ip_off;
      write_ip_hdr->ip_ttl = ipHeader->ip_ttl - 1;
      write_ip_hdr->ip_p = ipHeader->ip_p;
      write_ip_hdr->ip_sum = 0;
      write_ip_hdr->ip_src = ipHeader->ip_src;
      write_ip_hdr->ip_dst = natEntry->internal_ip;
      write_ip_hdr->ip_v = ipHeader->ip_v;
      write_ip_hdr->ip_hl = ipHeader->ip_hl;
      write_ip_hdr->ip_sum = cksum((const void *)write_ip_hdr, IP_SIZE);
      
      icmp_hdr *write_icmp_hdr = (icmp_hdr *)(bufferPtr + ETH_SIZE + IP_SIZE); 

      memcpy(write_icmp_hdr, recv_icmp, icmpSize);
      write_icmp_hdr->icmp_sum = 0;
    write_icmp_hdr->icmp_sum = cksum((const void *)write_icmp_hdr, icmpSize); 

    
      std::cout << " iface->addr.data()" << iface->addr.data() << std::endl;
       sendPacket(buffer,  iface->name);
      std::cout << "PACKET" << std::endl;
      print_hdrs(packet);
      std::cout << "BUFFER" << std::endl;
      print_hdrs(buffer);

    
    
  }
  if(ntohs(cksum((const void *)recv_icmp, icmpSize)) == 0XFFFF && recv_icmp->icmp_type == 8){

    if(true){
       std::cout << "ipHeader->ip_dst" << ipToString(ipHeader->ip_dst) << std::endl;
    std::cout << "ipHeader->ip_src" << ipToString(ipHeader->ip_src) << std::endl;

      std::shared_ptr<NatEntry> natEntry = m_natTable.lookup(recv_icmp->icmp_id);

    uint32_t ex_ip = findIfaceByName("sw0-eth4")->ip;
    std::cout << "sw0-eth3" << ipToString(ex_ip) << std::endl;
    std::cout << "sw0-eth4" << ipToString(ex_ip) << std::endl;
    if(natEntry == nullptr){
      std::cout << "~ nullptr ~" << std::endl;
      m_natTable.insertNatEntry(recv_icmp->icmp_id, ipHeader->ip_src, ex_ip);
      natEntry = m_natTable.lookup(recv_icmp->icmp_id);
    }
    else{
      natEntry->timeUsed = steady_clock::now();
    }

    ethernet_hdr *write_eth_hdr = (ethernet_hdr *)bufferPtr; 
   // memcpy(write_eth_hdr->ether_shost, eth_hdr->ether_shost, ETHER_ADDR_LEN);                       
  //  memcpy(write_eth_hdr->ether_dhost, eth_hdr->ether_dhost, ETHER_ADDR_LEN); //destination is to send back to source
   // write_eth_hdr->ether_type = htons(ethertype_ip);
  // writeEthernetHeader(write_eth_hdr, eth_hdr, iface, htons(ethertype_ip));
   //shost -> routers address  lookup function (ipHeader -> dst)
   //dhost -> next hop host address (server or client) lookup function ipHeader -> dst
   // arp cache, arp request 
  
  writeEthernetHeader(write_eth_hdr, eth_hdr, iface, htons(ethertype_ip));
  
  //memcpy(write_eth_hdr, eth_hdr, ETH_SIZE );
 //   memcpy(write_eth_hdr->ether_shost, iface->addr.data(), ETHER_ADDR_LEN);                       
  //memcpy(write_eth_hdr->ether_dhost, arpEntry->mac.data(), ETHER_ADDR_LEN); /
 
  

      ip_hdr *write_ip_hdr = (ip_hdr *)(bufferPtr + ETH_SIZE);
      write_ip_hdr->ip_tos = ipHeader->ip_tos;
      write_ip_hdr->ip_len = htons(IP_SIZE + icmpSize); 
      write_ip_hdr->ip_id = ipHeader->ip_id;
      write_ip_hdr->ip_off = ipHeader->ip_off;
      write_ip_hdr->ip_ttl = ipHeader->ip_ttl -1;
      write_ip_hdr->ip_p = ipHeader->ip_p;
      write_ip_hdr->ip_sum = 0;
      write_ip_hdr->ip_src = ipHeader->ip_dst;//natEntry->external_ip;
      write_ip_hdr->ip_dst =  ipHeader->ip_src;
      write_ip_hdr->ip_v = ipHeader->ip_v;
      write_ip_hdr->ip_hl = ipHeader->ip_hl;
      write_ip_hdr->ip_sum = cksum((const void *)write_ip_hdr, IP_SIZE);
      
      icmp_hdr *write_icmp_hdr = (icmp_hdr *)(bufferPtr + ETH_SIZE + IP_SIZE);

    //  memcpy(write_icmp_hdr, recv_icmp, icmpSize);
  writeIcmpHeader(write_icmp_hdr, recv_icmp, icmpSize);     
      //write_icmp_hdr->icmp_sum = 0;
    //  write_icmp_hdr->icmp_sum = cksum((const void *)write_icmp_hdr, icmpSize); 

    
      std::cout << " iface->addr.data()" << iface->addr.data() << std::endl;
       sendPacket(buffer,  iface->name);
      std::cout << "PACKET" << std::endl;
      print_hdrs(packet);
      std::cout << "BUFFER" << std::endl;
      print_hdrs(buffer);
    }
  }
}

void 
SimpleRouter::handleIcmp(const ip_hdr *ipHeader, const Buffer& packet, const ethernet_hdr *eth_hdr, const Interface *iface){
  std::size_t icmpSize = packet.size() -  ETH_SIZE - IP_SIZE;
  const icmp_hdr *recv_icmp = (icmp_hdr *)(packet.data() + ETH_SIZE + IP_SIZE);

  
  if (ntohs(cksum((const void *)recv_icmp, icmpSize)) == 0XFFFF && recv_icmp->icmp_type == 8)
  {
     std::cout << "ECHO REQUEST" << std::endl;

      Buffer buffer(IP_SIZE + ETH_SIZE + icmpSize); 

      uint8_t *bufferPtr = (uint8_t *)buffer.data();

      ethernet_hdr *write_eth_hdr = (ethernet_hdr *)bufferPtr; 
      writeEthernetHeader(write_eth_hdr, eth_hdr, iface, htons(ethertype_ip));

      ip_hdr *write_ip_hdr = (ip_hdr *)(bufferPtr + ETH_SIZE); 
      writeIcmpIpHeader(write_ip_hdr, ipHeader, icmpSize);

      icmp_hdr *write_icmp_hdr = (icmp_hdr *)(bufferPtr + ETH_SIZE + IP_SIZE);
      writeIcmpHeader(write_icmp_hdr, recv_icmp, icmpSize);

      sendPacket(buffer, iface->name); 
      print_hdrs(buffer);
    
  }
  
}

void
SimpleRouter::handleArp(const Buffer& packet, const ethernet_hdr *eth_hdr, const Interface *iface){
  const arp_hdr *arpHdr = reinterpret_cast<const arp_hdr *>(packet.data() + ETH_SIZE); 
  uint16_t opcode = ntohs(arpHdr->arp_op);

  if (opcode == arp_op_reply) {
    handleArpReply(arpHdr, eth_hdr, iface);
  }
  if (opcode == arp_op_request) {
    handleArpRequest(arpHdr, eth_hdr, iface);
  }
}
  
void
SimpleRouter::handleArpRequest(const arp_hdr *arpHdr, const ethernet_hdr *eth_hdr, const Interface *iface){
  std::cout << "ARP_REQUEST" << std::endl;
  Buffer reply(ARP_SIZE + ETH_SIZE); 
  uint8_t *ptrReply = (uint8_t *)reply.data();

  ethernet_hdr *write_eth_hdr = (ethernet_hdr *)ptrReply; 
  writeEthernetHeader(write_eth_hdr, eth_hdr, iface, htons(ethertype_arp));

  arp_hdr *write_arp_hdr = (arp_hdr *)(ptrReply + ETH_SIZE); 
  writeArpHeader(write_arp_hdr, htons(arp_op_reply), iface, arpHdr->arp_sip );
  memcpy(write_arp_hdr->arp_tha, &(arpHdr->arp_sha), ETHER_ADDR_LEN);
  
  sendPacket(reply, iface->name); 
}

void
SimpleRouter::handleArpReply(const arp_hdr *arpHdr, const ethernet_hdr *eth_hdr, const Interface *iface){
  std::cout << "ARP_REPLY" << std::endl;
  std::shared_ptr<simple_router::ArpEntry> arpLookup = m_arp.lookup(arpHdr->arp_sip);
  const Buffer buffer(std::begin(arpHdr->arp_sha), std::end(arpHdr->arp_sha));

   std::shared_ptr<ArpRequest> arpRequest = m_arp.insertArpEntry(buffer, arpHdr->arp_sip);
  if(arpRequest == nullptr){
    return;
  }
  else {
    
   // std::shared_ptr<ArpRequest> arpRequest = m_arp.insertArpEntry(buffer, arpHdr->arp_sip);
    std::cout << "arp_req" << arpRequest << std::endl;
   
    for (const auto &p : arpRequest->packets) 
    {
      Buffer currPacket = p.packet;
      Buffer sendPack(currPacket.size());

      memcpy(sendPack.data(), currPacket.data(), currPacket.size()); 
      uint8_t *ptr = (uint8_t *)sendPack.data();
      ethernet_hdr *write_eth_hdr = (ethernet_hdr *) ptr;
  
      memcpy(write_eth_hdr->ether_shost, iface->addr.data(), ETHER_ADDR_LEN);
      memcpy(write_eth_hdr->ether_dhost, arpHdr->arp_sha, ETHER_ADDR_LEN);
      write_eth_hdr->ether_type = htons(ethertype_ip);

      ip_hdr *write_ip_hdr = (ip_hdr *)(ptr + ETH_SIZE);
      writeIpHeader(write_ip_hdr);

      sendPacket(sendPack, iface->name); 
      
    }
    m_arp.removeRequest(arpRequest);
  }
}

void
SimpleRouter::writeEthernetHeader(ethernet_hdr *write_eth_hdr, const ethernet_hdr *eth_hdr, const Interface *iface, unsigned short type){
  memcpy(write_eth_hdr->ether_shost, iface->addr.data(), ETHER_ADDR_LEN);                       
  memcpy(write_eth_hdr->ether_dhost, eth_hdr->ether_shost, ETHER_ADDR_LEN); 
  write_eth_hdr->ether_type = type;
}

void
SimpleRouter::writeIpHeader(ip_hdr *write_ip_hdr){
  write_ip_hdr->ip_ttl -= 1;
  write_ip_hdr->ip_sum = 0;
  write_ip_hdr->ip_sum = cksum((const void *)write_ip_hdr, IP_SIZE);
}

void
SimpleRouter::writeIcmpIpHeader(ip_hdr *write_ip_hdr, const ip_hdr *ipHeader, std::size_t icmpSize){
  write_ip_hdr->ip_tos = 0;
  write_ip_hdr->ip_len = htons(IP_SIZE + icmpSize); 
  write_ip_hdr->ip_id = 0;
  write_ip_hdr->ip_off = htons(IP_DF);
  write_ip_hdr->ip_ttl = 64;
  write_ip_hdr->ip_p = ip_protocol_icmp;
  write_ip_hdr->ip_sum = 0;
  write_ip_hdr->ip_src = ipHeader->ip_dst;
  write_ip_hdr->ip_dst = ipHeader->ip_src;
  write_ip_hdr->ip_v = 4;
  write_ip_hdr->ip_hl = 5;
  write_ip_hdr->ip_sum = cksum((const void *)write_ip_hdr, IP_SIZE);
}

void
SimpleRouter::writeIcmpHeader(icmp_hdr *write_icmp_hdr, const icmp_hdr *recv_icmp, std::size_t icmpSize){
  memcpy(write_icmp_hdr, recv_icmp, icmpSize);
  write_icmp_hdr->icmp_code = 0;
  write_icmp_hdr->icmp_sum = 0;
  write_icmp_hdr->icmp_type = 0;
  write_icmp_hdr->icmp_sum = cksum((const void *)write_icmp_hdr, icmpSize); 
}

void
SimpleRouter::writeArpHeader(arp_hdr *write_arp_hdr, unsigned short type, const Interface *iface, uint32_t tip){
  write_arp_hdr->arp_hrd = htons(arp_hrd_ethernet);
  write_arp_hdr->arp_pro = htons(ethertype_ip);
  write_arp_hdr->arp_hln = ETHER_ADDR_LEN;
  write_arp_hdr->arp_pln = 4;
  ////
  write_arp_hdr->arp_op = type;
  memcpy(write_arp_hdr->arp_sha, iface->addr.data(), ETHER_ADDR_LEN); 
  write_arp_hdr->arp_sip = iface->ip;
  write_arp_hdr->arp_tip = tip;
}

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

// You should not need to touch the rest of this code.
SimpleRouter::SimpleRouter()
  : m_arp(*this)
  , m_natTable(*this)
{
}

void
SimpleRouter::sendPacket(const Buffer& packet, const std::string& outIface)
{
  m_pox->begin_sendPacket(packet, outIface);
}

bool
SimpleRouter::loadRoutingTable(const std::string& rtConfig)
{
  return m_routingTable.load(rtConfig);
}

void
SimpleRouter::loadIfconfig(const std::string& ifconfig)
{
  std::ifstream iff(ifconfig.c_str());
  std::string line;
  while (std::getline(iff, line)) {
    std::istringstream ifLine(line);
    std::string iface, ip;
    ifLine >> iface >> ip;

    in_addr ip_addr;
    if (inet_aton(ip.c_str(), &ip_addr) == 0) {
      throw std::runtime_error("Invalid IP address `" + ip + "` for interface `" + iface + "`");
    }

    m_ifNameToIpMap[iface] = ip_addr.s_addr;
  }
}

void
SimpleRouter::printIfaces(std::ostream& os)
{
  if (m_ifaces.empty()) {
    os << " Interface list empty " << std::endl;
    return;
  }

  for (const auto& iface : m_ifaces) {
    os << iface << "\n";
  }
  os.flush();
}

const Interface*
SimpleRouter::findIfaceByIp(uint32_t ip) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [ip] (const Interface& iface) {
      return iface.ip == ip;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}

const Interface*
SimpleRouter::findIfaceByMac(const Buffer& mac) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [mac] (const Interface& iface) {
      return iface.addr == mac;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}

void
SimpleRouter::reset(const pox::Ifaces& ports)
{
  std::cerr << "Resetting SimpleRouter with " << ports.size() << " ports" << std::endl;

  m_arp.clear();
  m_ifaces.clear();

  for (const auto& iface : ports) {
    auto ip = m_ifNameToIpMap.find(iface.name);
    if (ip == m_ifNameToIpMap.end()) {
      std::cerr << "IP_CONFIG missing information about interface `" + iface.name + "`. Skipping it" << std::endl;
      continue;
    }

    m_ifaces.insert(Interface(iface.name, iface.mac, ip->second));
  }

  printIfaces(std::cerr);
}

const Interface*
SimpleRouter::findIfaceByName(const std::string& name) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [name] (const Interface& iface) {
      return iface.name == name;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}


} // namespace simple_router {
