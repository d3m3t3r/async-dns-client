// main.cpp

#include "logging.hpp"
#include "async-dns-client.hpp"

#include <future>
#include <iostream>

#include <unistd.h>  // getopt


void usage(const char* prog)
{
  std::cout << "Usage: " << prog << " [OPTION...] HOST...\n"
            << "    Options:\n"
               "      -h       This help\n"
               "      -s IP    Nameserver IP (default: 127.0.0.1)\n"
               "      -p PORT  Nameserver port (default: 53)\n"
               "      -w N     Number of thread workers (0 == #cores, default: 0)\n"
               "      -t MS    Query timeout in milliseconds (default: 2000)\n"
               "      -6       Make AAAA query rather than A\n"
               "      -v       Verbose logging (use multiple times)\n";
}

int main(int argc, char* argv[])
{
  std::string ns_ip = "127.0.0.1";
  unsigned short ns_port = 53;
  std::size_t n_workers = 0;
  unsigned int timeout_ms = 2000;
  bool ipv6 = false;
  unsigned int verbose = 0;

  int opt;
  while ((opt = getopt(argc, argv, "s:p:w:t:6vh")) != -1) {
    switch (opt) {
      case 's':
        ns_ip = optarg;
        break;
      case 'p':
        ns_port = std::atoi(optarg);
        break;
      case 'w':
        n_workers = std::atoi(optarg);
        break;
      case 't':
        timeout_ms = std::atoi(optarg);
        break;
      case '6':
        ipv6 = true;
        break;
      case 'v':
        ++verbose;
        break;
      case 'h':
        usage(argv[0]);
        return 0;
      default:
        usage(argv[0]);
        return 1;
    }
  }

  if (optind == argc) {
    usage(argv[0]);
    return 0;
  }

  // Set the logging threshold to ERROR.
  logger().set_threshold(Logger::Level((unsigned int)Logger::Level::ERROR + verbose));

  if (n_workers == 0) {
    n_workers = std::thread::hardware_concurrency();
  }

  INFO() << "nameserver=" << ns_ip << ":" << ns_port
         << ", workers=" << n_workers
         << ", timeout=" << timeout_ms
         << ", ipv6=" << ipv6;

  AsyncDnsClient dns(ns_ip, ns_port, n_workers, timeout_ms);
  dns.start();

  std::promise<void> done;
  std::size_t n = argc - optind;

  auto on_finished = [&done, &n](AsyncDnsClient::QueryResult result,
                                 std::string_view name,
                                 AsyncDnsClient::QueryType type,
                                 int rcode,
                                 std::vector<std::pair<std::string, boost::asio::ip::address>>&& addrs,
                                 std::vector<std::pair<std::string, std::string>>&& cnames) {
    std::cout << name << ": " << result << "\n"
              << "  rcode=" << rcode << "\n";
    for (auto&& [name, ip]: addrs) {
      std::cout << "  " << name << " " << type << " " << ip << std::endl;
    }

    for (auto&& [name, cname]: cnames) {
      std::cout << "  " << name << " CNAME " << cname << std::endl;
    }

    if (--n == 0) {
      done.set_value();
    }
  };

  for (int i = optind; i < argc; ++i) {
    dns.async_query(
        argv[i], ipv6 ? AsyncDnsClient::TYPE_AAAA : AsyncDnsClient::TYPE_A, on_finished);
  }

  done.get_future().wait();
  dns.stop();

  return 0;
}
