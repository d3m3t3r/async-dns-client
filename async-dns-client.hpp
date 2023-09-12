// async-dns-client.hpp

#pragma once

#include <boost/asio/io_context.hpp>
#include <boost/asio/io_context_strand.hpp>
#include <boost/asio/ip/address.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/steady_timer.hpp>

#include <string_view>
#include <string>
#include <functional>
#include <memory>
#include <thread>
#include <vector>
#include <map>


//
// Asynchronnous DNS client
//
class AsyncDnsClient
{
public:
  enum QueryType { TYPE_A, TYPE_AAAA };

  enum QueryResult { RESULT_SUCCESS, RESULT_TIMEOUT, RESULT_ERROR };

  using OnFinishedCallback = std::function<
      void(QueryResult result,
           std::string_view name,
           QueryType type,
           int rcode,
           std::vector<std::pair<std::string, boost::asio::ip::address>>&& addrs,
           std::vector<std::pair<std::string, std::string>>&& cnames)>;

  AsyncDnsClient(std::string_view ns_ip, unsigned short ns_port = 53,
                 std::size_t n_workers = 1,
                 unsigned int timeout_ms = 500);

  void start();
  void stop();

  void async_query(std::string_view name, QueryType type, const OnFinishedCallback& on_finished_cb);

private:
  struct Query
  {
    Query(boost::asio::io_context::strand& io, std::string_view name, QueryType type, OnFinishedCallback cb);

    const std::string name;
    const QueryType type;
    OnFinishedCallback cb;
    boost::asio::steady_timer timer;
    bool done;
    std::vector<unsigned char> request;
    unsigned int id;
  };

  friend std::ostream& operator<<(std::ostream& os, const Query& query);

  void start_receiving();

  const boost::asio::ip::udp::endpoint nameserver_;
  const std::size_t n_workers_;
  const unsigned int timeout_ms_;

  boost::asio::io_context io_;
  boost::asio::executor_work_guard<boost::asio::io_context::executor_type> io_guard_;
  boost::asio::io_context::strand io_strand_;
  boost::asio::ip::udp::socket socket_;
  std::vector<std::thread> workers_;
  std::map<int, std::shared_ptr<Query>> queries_;
};

std::ostream& operator<<(std::ostream& os, const AsyncDnsClient::Query& query);
std::ostream& operator<<(std::ostream& os, const AsyncDnsClient::QueryType& type);
std::ostream& operator<<(std::ostream& os, const AsyncDnsClient::QueryResult& result);
