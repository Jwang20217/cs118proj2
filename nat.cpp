#include "nat.hpp"
#include "core/utils.hpp"
#include "core/interface.hpp"
#include "simple-router.hpp"

#include <algorithm>
#include <iostream>

namespace simple_router {

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
// IMPLEMENT THESE METHODS
void
NatTable::checkNatTable()
{
  std::map<uint16_t, std::shared_ptr<NatEntry>>::iterator it;
  std::list<uint16_t> removeEntries;
  for ( it = m_natTable.begin(); it != m_natTable.end(); it++ )
  {
      std::shared_ptr<NatEntry> entry = it->second;
      if(steady_clock::now() - entry->timeUsed >= SR_NAT_TO){
        removeEntries.push_back(it->first);
        std::cout << "ERASE from Nat Table id: " << it->first << std::endl;
      }
  }

  for(const auto& e: removeEntries){
    m_natTable.erase(e);
  }
  print();
}

std::shared_ptr<NatEntry>
NatTable::lookup(uint16_t id)
{
  std::map<uint16_t, std::shared_ptr<NatEntry>>::iterator it;
  for ( it = m_natTable.begin(); it != m_natTable.end(); it++ )
  {
      if(it->first == id)
        return it->second;
  }
  return nullptr;
}

void
NatTable::insertNatEntry(uint16_t id, uint32_t in_ip, uint32_t ex_ip)
{
  auto entry = std::make_shared<NatEntry>();
  entry->internal_ip = in_ip;
  entry->external_ip = ex_ip;
  entry->timeUsed = steady_clock::now();
  entry->isValid = true;

  m_natTable.insert( std::pair<uint16_t,std::shared_ptr<NatEntry>>(id,entry));
}

void
NatTable::print()
{
  
  std::cout << "NAT TABLE ENTRIES"  <<  std::endl;

  std::map<uint16_t, std::shared_ptr<NatEntry>>::iterator it;
  for(it = m_natTable.begin(); it != m_natTable.end(); ++it)
  {
    std::shared_ptr<NatEntry> second = it->second;
    std::cout << "ICMP ID: " << it->first << " internal_ip: " << ipToString(second->internal_ip) << " external_ip: " << ipToString(second->external_ip)  << std::endl;
  }
}

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

// You should not need to touch the rest of this code.

NatTable::NatTable(SimpleRouter& router)
  : m_router(router)
  , m_shouldStop(false)
  , m_tickerThread(std::bind(&NatTable::ticker, this))
{
}

NatTable::~NatTable()
{
  m_shouldStop = true;
  m_tickerThread.join();
}


void
NatTable::clear()
{
  std::lock_guard<std::mutex> lock(m_mutex);

  m_natTable.clear();
}

void
NatTable::ticker()
{
  while (!m_shouldStop) {
    std::this_thread::sleep_for(std::chrono::seconds(1));

    {
      std::lock_guard<std::mutex> lock(m_mutex);

      auto now = steady_clock::now();

      std::map<uint16_t, std::shared_ptr<NatEntry>>::iterator entryIt;
      for (entryIt = m_natTable.begin(); entryIt != m_natTable.end(); entryIt++ ) {
        if (entryIt->second->isValid && (now - entryIt->second->timeUsed > SR_ARPCACHE_TO)) {
          entryIt->second->isValid = false;
        }
      }

      checkNatTable();
    }
  }
}

std::ostream&
operator<<(std::ostream& os, const NatTable& table)
{
  std::lock_guard<std::mutex> lock(table.m_mutex);

  os << "\nID            Internal IP         External IP             AGE               VALID\n"
     << "-----------------------------------------------------------------------------------\n";

  auto now = steady_clock::now();

  for (auto const& entryIt : table.m_natTable) {
    os << entryIt.first << "            "
       << ipToString(entryIt.second->internal_ip) << "         "
       << ipToString(entryIt.second->external_ip) << "         "
       << std::chrono::duration_cast<seconds>((now - entryIt.second->timeUsed)).count() << " seconds         "
       << entryIt.second->isValid
       << "\n";
  }
  os << std::endl;
  return os;
}

} // namespace simple_router
