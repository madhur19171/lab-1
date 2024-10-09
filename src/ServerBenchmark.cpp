/**
 * ServerBenchmark.cpp
 * Author: Ethan Graham
 */

#include <bpf/bpf.h>
#include <getopt.h>
#include <net/if.h>
#include <unistd.h>

#include <ServerBenchmark.hpp>
#include <Skeleton.cpp>
#include <iostream>
#include <ostream>
#include <string>
#include <thread>
#include <vector>

#include "ProcParser.cpp"

#define THRESHOLD_DELAY 200000 /* 200us delay threshold */

#define GET_FD(fd, map_name)                   \
  fd = bpf_map__fd(skel.get()->maps.map_name); \
  if (fd == -EINVAL) return -1;

#define SET_MAX_ENTRIES(map_name, value) \
  if (bpf_map__set_max_entries(skel.get()->maps.map_name, value) < 0) return -1;

#define CPUMAP_QUERY "cpumap"
#define BUFFER_SIZE 1024
#define CPU_ADDED_TIMESTAMPS_FILEPATH "server_results/cpu_added_timestamps.txt"

int redirectProgRoundRobin(std::vector<int>& cpus, std::string& ifname, __u16 port, int duration) {
  int err;
  int portFd, availFd, mapFd, iterFd, countFd, devmapFd, txCtrFd, rxCtrFd, totalSrvTimeFd;
  int maxCpus;
  __u32 key0 = 0;
  auto skel = Skeleton<bpfnic>();
  auto procParser = ProcParser(CPUMAP_QUERY);

  struct bpf_object_open_opts opts;
  memset(&opts, 0, sizeof(struct bpf_object_open_opts));
  opts.sz = sizeof(struct bpf_object_open_opts);
  err = skel.open(&opts);
  if (err) {
    std::cerr << "Unable to open skel: " << strerror(err) << std::endl;
    return -1;
  } else {
    std::cout << "successfully opened skel" << std::endl;
  }

  maxCpus = libbpf_num_possible_cpus();
  SET_MAX_ENTRIES(cpu_map, maxCpus);
  SET_MAX_ENTRIES(cpus_available, maxCpus);
  SET_MAX_ENTRIES(cpus_available_long_reqs, maxCpus);
  SET_MAX_ENTRIES(cpus_available_short_reqs, maxCpus);

  err = skel.load();
  if (err) {
    std::cerr << "err load: " << err << std::endl;
    return -1;
  } else {
    std::cout << "successfully loaded skel" << std::endl;
  }

  /* initialize the file descriptors */
  GET_FD(portFd, port_num);
  GET_FD(mapFd, cpu_map);
  GET_FD(countFd, cpus_count);
  GET_FD(availFd, cpus_available);
  GET_FD(iterFd, cpu_iter);
  GET_FD(devmapFd, devmap);
  GET_FD(txCtrFd, tx_packet_ctr);
  GET_FD(rxCtrFd, rx_packet_ctr);
  GET_FD(totalSrvTimeFd, total_srv_time);

  __u32 cpusSize = cpus.size();

  int cpuProgFd = bpf_program__fd(skel.get()->progs.bpfnic_benchmark_cpu_func);

  struct bpf_cpumap_val *cpumapVal = (struct bpf_cpumap_val *)malloc(sizeof(struct bpf_cpumap_val));
  cpumapVal->qsize = (1 << 12);  // big queue
  cpumapVal->bpf_prog.fd = cpuProgFd;

  // update cpumap with bpf programs
  for (__u32 i = 0; i < (__u32)cpusSize; i++) {
    __u32 currCpu = cpus.at(i);
    if ((err = bpf_map_update_elem(availFd, &i, &currCpu, 0))) {
      std::cout << "Failed to create avail entry " << i << ": " << strerror(errno) << std::endl;
      exit(1);
    }

    if ((err = bpf_map_update_elem(mapFd, &currCpu, cpumapVal, 0))) {
      std::cout << "Failed to create cpumap entry " << i << ": " << strerror(errno) << std::endl;
      exit(1);
    }
  }

  err = bpf_map_update_elem(portFd, &key0, &port, 0);
  bpf_map_update_elem(countFd, &key0, &cpusSize, 0);

  int ifindex = if_nametoindex(ifname.c_str());
  if (!ifindex) {
    std::cout << "Failed to find ifindex for " << ifname << ": " << strerror(errno) << std::endl;
    exit(1);
  }

  struct bpf_devmap_val devmapEntry = {.ifindex = (__u32)ifindex};
  bpf_map_update_elem(devmapFd, &key0, &devmapEntry, 0);

  // attach xdp program
  auto link = bpf_program__attach_xdp(skel.get()->progs.bpf_redirect_roundrobin, ifindex);
  if (!link) exit(1);

  std::cout << "Program loaded on " << ifname << "; " << ifindex << std::endl;

  __u64 txValues[BUFFER_SIZE] = {0};
  __u64 srvTimes[BUFFER_SIZE] = {0};
  __u64 rxValue = 0;
  bpf_map_update_elem(txCtrFd, &key0, txValues, 0);
  bpf_map_update_elem(totalSrvTimeFd, &key0, srvTimes, 0);
  bpf_map_update_elem(rxCtrFd, &key0, &rxValue, 0);

  /* MAIN LOOP */
  for (int time = 0; time < duration; time++) {
    /* book-keeping */
    __u64 totalTxPackets = 0;
    if (bpf_map_lookup_elem(txCtrFd, &key0, txValues)) exit(1);
    if (bpf_map_lookup_elem(totalSrvTimeFd, &key0, srvTimes)) exit(1);
    if (bpf_map_lookup_elem(rxCtrFd, &key0, &rxValue)) exit(1);

    /* DISPLAY */
    system("clear");
    std::cout << "\nCycle Summary. Iter N° " << time << " out of " << duration << "\n";
    std::cout << "\tAvg. queuing delays\n";

    for (int i = 0; i < BUFFER_SIZE; i++) {
      totalTxPackets += txValues[i];

      if (srvTimes[i] > 0 && txValues[i] > 0) {
        std::cout << "\t\tcpu_" << i << " = " << ((double)srvTimes[i] / txValues[i]) / 1000.0 << " μs\n";
      }
    }

    // clear arrays - state is kept per-window
    std::fill(std::begin(srvTimes), std::end(srvTimes), 0);
    std::fill(std::begin(txValues), std::end(txValues), 0);

    __u64 zero = 0;
    bpf_map_update_elem(txCtrFd, &key0, txValues, 0);
    bpf_map_update_elem(totalSrvTimeFd, &key0, srvTimes, 0);
    bpf_map_update_elem(rxCtrFd, &key0, &zero, 0);

    std::cout << "\n\treceived " << rxValue << " |  sent " << totalTxPackets << "\n";

    auto cpuUtilizations = procParser.getCpuUtilizationVec();

    std::cout << "\tCpu utizations: " << std::endl;
    for (unsigned int i = 0; i < cpuUtilizations.size(); i++) {
      std::cout << "\t\t" << procParser.getKeyWord() << "_" << cpus.at(i) << ": " << cpuUtilizations.at(i) * 100.0
                << "% \n";
    }
    std::cout << std::endl;  // flush stdout
    std::this_thread::sleep_for(std::chrono::seconds(1));
  }

  return 0;
}

int redirectProgRoundRobinCoreSeparated(std::vector<int>& cpusShort, std::vector<int>& cpusLong, std::string& ifname,
                                        __u16 port, int duration) {
  int err;
  int portFd, availShortFd, availLongFd, mapFd, iterFd, countFd, devmapFd, txCtrFd, rxCtrFd, totalSrvTimeFd;
  int numCpus;
  __u32 key0 = 0;
  __u32 key1 = 1;
  auto skel = Skeleton<bpfnic>();
  auto procParser = ProcParser("cpumap");

  struct bpf_object_open_opts opts;
  memset(&opts, 0, sizeof(struct bpf_object_open_opts));
  opts.sz = sizeof(struct bpf_object_open_opts);
  err = skel.open(&opts);
  if (err) {
    std::cout << "Unable to open skel: " << strerror(err) << std::endl;
    return -1;
  } else {
    std::cout << "successfully opened skel" << std::endl;
  }

  numCpus = libbpf_num_possible_cpus();
  SET_MAX_ENTRIES(cpu_map, numCpus);
  SET_MAX_ENTRIES(cpus_available, numCpus);
  SET_MAX_ENTRIES(cpus_available_long_reqs, numCpus);
  SET_MAX_ENTRIES(cpus_available_short_reqs, numCpus);

  err = skel.load();
  if (err) {
    std::cout << "err load: " << err << std::endl;
    return -1;
  } else {
    std::cout << "successfully loaded skel" << std::endl;
  }

  GET_FD(portFd, port_num);
  GET_FD(mapFd, cpu_map);
  GET_FD(countFd, cpu_count_core_separated);
  GET_FD(availShortFd, cpus_available_short_reqs);
  GET_FD(availLongFd, cpus_available_long_reqs);
  GET_FD(iterFd, cpu_iter_core_separated);
  GET_FD(devmapFd, devmap);
  GET_FD(txCtrFd, tx_packet_ctr);
  GET_FD(rxCtrFd, rx_packet_ctr);
  GET_FD(totalSrvTimeFd, total_srv_time);

  __u32 cpusShortSize = cpusShort.size();
  __u32 cpusLongSize = cpusLong.size();
  bpf_map_update_elem(countFd, &key0, &cpusShortSize, 0);
  bpf_map_update_elem(countFd, &key1, &cpusLongSize, 0);

  cpusShortSize = 0;
  cpusLongSize = 0;
  bpf_map_lookup_elem(countFd, &key0, &cpusShortSize);
  bpf_map_lookup_elem(countFd, &key1, &cpusLongSize);

  int ret;

  int cpuProgFd = bpf_program__fd(skel.get()->progs.bpfnic_benchmark_cpu_func);
  struct bpf_cpumap_val *val = (struct bpf_cpumap_val *)malloc(sizeof(struct bpf_cpumap_val));
  val->qsize = (1 << 12);  // big queue
  val->bpf_prog.fd = cpuProgFd;

  // add all short-request-reserved CPUs to needed maps
  for (__u32 i = 0; i < (__u32)cpusShortSize; i++) {
    __u32 currCpu = cpusShort.at(i);
    std::cout << "adding cpu_" << cpusShort.at(i) << " to short cpus" << std::endl;
    if ((ret = bpf_map_update_elem(availShortFd, &i, &currCpu, 0))) {
      std::cout << "Failed to create avail entry " << i << ": " << strerror(errno) << std::endl;
      exit(1);
    }

    if ((ret = bpf_map_update_elem(mapFd, &currCpu, val, 0))) {
      std::cout << "Failed to create cpumap entry " << i << ": " << strerror(errno) << std::endl;
      exit(1);
    }
  }

  // add all long-request-reserved CPUs to needed maps
  for (__u32 i = 0; i < (__u32)cpusLongSize; i++) {
    __u32 currCpu = cpusLong.at(i);
    std::cout << "adding cpu_" << cpusLong.at(i) << " to long cpus" << std::endl;
    if ((ret = bpf_map_update_elem(availLongFd, &i, &currCpu, 0))) {
      std::cout << "Failed to create avail entry " << i << ": " << strerror(errno) << std::endl;
      exit(1);
    }

    if ((ret = bpf_map_update_elem(mapFd, &currCpu, val, 0))) {
      std::cout << "Failed to create cpumap entry " << i << ": " << strerror(errno) << std::endl;
      exit(1);
    }
  }

  ret = bpf_map_update_elem(portFd, &key0, &port, 0);
  __u16 portTest;
  bpf_map_lookup_elem(portFd, &key0, &portTest);
  std::cout << "Port set to = " << portTest << std::endl;

  bpf_map_update_elem(countFd, &key0, &cpusShortSize, 0);
  bpf_map_update_elem(countFd, &key1, &cpusLongSize, 0);

  int ifindex = if_nametoindex(ifname.c_str());
  if (!ifindex) {
    std::cout << "Failed to find ifindex for " << ifname << ": " << strerror(errno) << std::endl;
    exit(0);
  }

  struct bpf_devmap_val devmapEntry = {.ifindex = (__u32)ifindex};
  bpf_map_update_elem(devmapFd, &key0, &devmapEntry, 0);

  auto link = bpf_program__attach_xdp(skel.get()->progs.bpf_redirect_roundrobin_core_separated, ifindex);

  if (!link) exit(1);

  std::cout << "Loaded on " << ifname << "; " << ifindex << std::endl;

  __u64 txValues[BUFFER_SIZE] = {0};
  __u64 srvTimes[BUFFER_SIZE] = {0};
  __u64 rxValue = 0;

  // set counters to 0 initially
  // bpf_map_update_elem(txCtrFd, &key0, txValues, 0);
  // bpf_map_update_elem(rxCtrFd, &key0, &rxValue, 0);

  std::ofstream rxTxFile("server_results/rx_tx.csv");
  rxTxFile << "rx,tx" << std::endl;

  /* MAIN LOOP */
  for (int time = 0; time < duration; time++) {
    /* book-keeping */
    __u64 totalTxPackets = 0;
    if (bpf_map_lookup_elem(txCtrFd, &key0, txValues)) exit(1);
    if (bpf_map_lookup_elem(totalSrvTimeFd, &key0, srvTimes)) exit(1);
    if (bpf_map_lookup_elem(rxCtrFd, &key0, &rxValue)) exit(1);

    /* DISPLAY */
    system("clear");
    std::cout << "\nCycle Summary. Iter N° " << time << " out of " << duration << "\n";

    std::cout << "Short core group = [ ";
    for (int cpu : cpusShort) std::cout << cpu << ", ";
    std::cout << "]\n";

    std::cout << "Long core group = [ ";
    for (int cpu : cpusLong) std::cout << cpu << ", ";
    std::cout << "]\n";

    // sanity check
    std::cout << "count short = " << cpusShortSize << ", count long = " << cpusLongSize << "\n";

    std::cout << "\tAvg. queuing delays\n";

    for (int i = 0; i < BUFFER_SIZE; i++) {
      totalTxPackets += txValues[i];

      if (srvTimes[i] > 0 && txValues[i] > 0) {
        std::cout << "\t\tcpu_" << i << " = " << ((double)srvTimes[i] / txValues[i]) / 1000.0 << " μs\n";
      }
    }

    // clear arrays - state is kept per-window
    std::fill(std::begin(srvTimes), std::end(srvTimes), 0);
    std::fill(std::begin(txValues), std::end(txValues), 0);

    __u64 zero = 0;
    bpf_map_update_elem(txCtrFd, &key0, txValues, 0);
    bpf_map_update_elem(totalSrvTimeFd, &key0, srvTimes, 0);
    bpf_map_update_elem(rxCtrFd, &key0, &zero, 0);

    std::cout << "\n\treceived " << rxValue << " |  sent " << totalTxPackets << "\n";
    rxTxFile << rxValue << "," << totalTxPackets << std::endl;

    auto cpuUtilizations = procParser.getCpuUtilizationVec();

    std::cout << "\tCpu utizations: " << std::endl;
    for (unsigned int i = 0; i < cpuUtilizations.size(); i++) {
      int cpu;
      if (i < cpusShortSize)
        cpu = cpusShort.at(i);
      else
        cpu = cpusLong.at(i - cpusShortSize);

      std::cout << "\t\t" << procParser.getKeyWord() << "_" << cpu << ": " << cpuUtilizations.at(i) * 100.0 << "% \n";
    }
    std::cout << std::endl;  // flush stdout
    std::this_thread::sleep_for(std::chrono::seconds(1));
  }

  return 0;
}

#define MAX_CPUS 8
#define MIN_CPUS 1

/// adds one CPU to the core group
void addOneCPU(int countFd) {
  int cpuCount;
  int key0 = 0;
  if (bpf_map_lookup_elem(countFd, &key0, &cpuCount)) exit(1);

  // TODO: Code to add a CPU
  // cpuCount after lookup will contain the current value
  if (cpuCount >= MAX_CPUS) return; // Can't add more than MAX_CPUS cores

  cpuCount++;
  if (bpf_map_update_elem(countFd, &key0, &cpuCount, 0)) exit(1);
}

/// removes one CPU from the core group
void removeOneCPU(int countFd) {
  int cpuCount;
  int key0 = 0;
  if (bpf_map_lookup_elem(countFd, &key0, &cpuCount)) exit(1);

  // TODO: Code to remove a CPU
  // cpuCount after lookup will contain the current value
  if (cpuCount <= MIN_CPUS) return; // Can't remove more than MIN_CPUS

  cpuCount--;
  if (bpf_map_update_elem(countFd, &key0, &cpuCount, 0)) exit(1);
}

/// @return the average queuing delay across all cores that have sent packets
double computeAverageQueuingDelay(int totalSrvTimeFd, int txCtrFd) {
  int key0 = 0;
  __u64 txValues[BUFFER_SIZE] = {0};  // holds the number of received packets per-cpu
  __u64 srvTimes[BUFFER_SIZE] = {0};  // holds the total queuing delay time per-cpu

  if (bpf_map_lookup_elem(txCtrFd, &key0, txValues)) exit(1);
  if (bpf_map_lookup_elem(totalSrvTimeFd, &key0, srvTimes)) exit(1);

  __u64 totalQueuingDelay = 0;
  __u64 totalTxPackets = 0;
  for (int i = 0; i < BUFFER_SIZE; i++) {
    totalQueuingDelay += srvTimes[i];
    totalTxPackets += txValues[i];
  }

  return totalTxPackets > 0 ? (double)totalQueuingDelay / (double)totalTxPackets : 0.0;
}

int redirectProgDynamicCoreAllocation(std::vector<int>& availCpus, std::string& ifname, __u16 port, int duration) {
  int err;
  int portFd, availFd, mapFd, iterFd, countFd, devmapFd, txCtrFd, rxCtrFd, totalSrvTimeFd;
  int cpumapProgFd;
  int numCpus;
  __u32 key0 = 0;
  std::vector<int> coreGroup;
  auto skel = Skeleton<bpfnic>();
  auto procParser = ProcParser(CPUMAP_QUERY);

  struct bpf_object_open_opts opts;
  memset(&opts, 0, sizeof(struct bpf_object_open_opts));
  opts.sz = sizeof(struct bpf_object_open_opts);
  err = skel.open(&opts);
  if (err) {
    std::cout << "Unable to open skel: " << strerror(err) << std::endl;
    return -1;
  } else {
    std::cout << "successfully opened skel" << std::endl;
  }

  numCpus = libbpf_num_possible_cpus();
  SET_MAX_ENTRIES(cpu_map, numCpus);
  SET_MAX_ENTRIES(cpus_available, numCpus);
  SET_MAX_ENTRIES(cpus_available_long_reqs, numCpus);
  SET_MAX_ENTRIES(cpus_available_short_reqs, numCpus);

  err = skel.load();
  if (err) {
    std::cout << "err load: " << err << std::endl;
    return -1;
  } else {
    std::cout << "successfully loaded skel" << std::endl;
  }

  GET_FD(portFd, port_num);
  GET_FD(mapFd, cpu_map);
  GET_FD(countFd, cpus_count);
  GET_FD(availFd, cpus_available);
  GET_FD(iterFd, cpu_iter);
  GET_FD(devmapFd, devmap);
  GET_FD(txCtrFd, tx_packet_ctr);
  GET_FD(rxCtrFd, rx_packet_ctr);
  GET_FD(totalSrvTimeFd, total_srv_time);

  cpumapProgFd = bpf_program__fd(skel.get()->progs.bpfnic_benchmark_cpu_func);

  // initialize cpumap programs
  struct bpf_cpumap_val *val = (struct bpf_cpumap_val *)malloc(sizeof(struct bpf_cpumap_val));
  val->qsize = (1 << 12);
  val->bpf_prog.fd = cpumapProgFd;

  // insert into the cpumap
  for (__u32 i = 0; i < (__u32)availCpus.size(); i++) {
    __u32 currCpu = availCpus.at(i);

    if ((err = bpf_map_update_elem(availFd, &i, &currCpu, 0))) exit(1);
    if ((err = bpf_map_update_elem(mapFd, &currCpu, val, 0))) exit(1);
  }

  bpf_map_update_elem(portFd, &key0, &port, 0);

  int ifindex = if_nametoindex(ifname.c_str());
  if (!ifindex) {
    std::cout << "Failed to find ifindex for " << ifname << ": " << strerror(errno) << std::endl;
    exit(0);
  }

  struct bpf_devmap_val devmapEntry = {.ifindex = (__u32)ifindex};
  bpf_map_update_elem(devmapFd, &key0, &devmapEntry, 0);

  auto link = bpf_program__attach_xdp(skel.get()->progs.bpf_redirect_roundrobin, ifindex);
  if (!link) exit(1);

  // we start with one cpu, and add more when threshold latency is surpassed
  __u32 cpusCount = MIN_CPUS;
  bpf_map_update_elem(countFd, &key0, &cpusCount, 0);

  std::cout << "Attached xdp program to " << ifname << ", ifindex=" << ifindex << std::endl;

  __u64 txValues[BUFFER_SIZE] = {0};  // holds the number of received packets per-cpu
  __u64 srvTimes[BUFFER_SIZE] = {0};  // holds the total queuing delay time per-cpu
  __u64 rxValue = 0;                  // holds the total number of received packets across all CPUs

  /* MAIN LOOP */
  for (int time = 0; time < duration; time++) {
    /* book-keeping */
    __u64 totalTxPackets = 0;
    if (bpf_map_lookup_elem(txCtrFd, &key0, txValues)) exit(1);
    if (bpf_map_lookup_elem(totalSrvTimeFd, &key0, srvTimes)) exit(1);
    if (bpf_map_lookup_elem(rxCtrFd, &key0, &rxValue)) exit(1);

    /* DISPLAY */
    system("clear");
    std::cout << "\nCycle Summary. Iter N° " << time << " out of " << duration << "\n";
    std::cout << "Core group size = " << cpusCount << "\n";
    std::cout << "\tAvg. queuing delays\n";

    for (int i = 0; i < BUFFER_SIZE; i++) {
      totalTxPackets += txValues[i];

      if (srvTimes[i] > 0 && txValues[i] > 0) {
        std::cout << "\t\tcpu_" << i << " = " << ((double)srvTimes[i] / txValues[i]) / 1000.0 << " μs\n";
      }
    }

    // BEGIN: CORE ADDITION LOGIC
    // TODO: Add logic to observe queueing delay and add cores
    if (computeAverageQueuingDelay(totalSrvTimeFd, rxCtrFd) > THRESHOLD_DELAY) {
      addOneCPU(countFd);
    }
    // END: CORE ADDITION LOGIC

    // clear arrays - state is kept per-window
    std::fill(std::begin(srvTimes), std::end(srvTimes), 0);
    std::fill(std::begin(txValues), std::end(txValues), 0);

    __u64 zero = 0;
    bpf_map_update_elem(txCtrFd, &key0, txValues, 0);
    bpf_map_update_elem(totalSrvTimeFd, &key0, srvTimes, 0);
    bpf_map_update_elem(rxCtrFd, &key0, &zero, 0);

    std::cout << "\n\treceived " << rxValue << " |  sent " << totalTxPackets << "\n";

    std::vector<double> cpuUtilizations = procParser.getCpuUtilizationVec();
    // the display logic assumes that `cpumap_i+1` is always parsed after
    // `cpumap_i`
    std::cout << "\tCpu utizations: " << std::endl;
    for (unsigned int i = 0; i < cpuUtilizations.size(); i++) {
      std::cout << "\t\t" << procParser.getKeyWord() << "_" << availCpus.at(i) << ": " << cpuUtilizations.at(i) * 100.0
                << "% \n";
    }
    std::cout << std::endl;  // flush stdout
    std::this_thread::sleep_for(std::chrono::seconds(1));
  }

  return 0;
}
