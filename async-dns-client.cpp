// async-dns-client.cpp

#include "async-dns-client.hpp"

#include "logging.hpp"

#include <boost/asio/bind_executor.hpp>

#include <chrono>
#include <cstring>  // std::memset

#include <arpa/nameser.h>
#include <resolv.h>


AsyncDnsClient::AsyncDnsClient(
        std::string_view ns_ip, unsigned short ns_port,
        std::size_t n_workers,
        unsigned int timeout_ms)
  : nameserver_(boost::asio::ip::make_address(ns_ip), ns_port),
    n_workers_(n_workers),
    timeout_ms_(timeout_ms),
    io_guard_(io_.get_executor()),
    io_strand_(io_),
    socket_(io_, nameserver_.protocol())
{}

void AsyncDnsClient::start()
{
  INFO() << "starting";

  for (std::size_t i = 0; i < n_workers_; ++i) {
    workers_.emplace_back([this]() { io_.run(); });
  }

  post(io_strand_, [this]() { start_receiving(); });
}

void AsyncDnsClient::stop()
{
  INFO() << "stopping";

  socket_.close();
  io_.stop();

  for (auto&& worker: workers_) {
    worker.join();
  }

  workers_.clear();
}

void AsyncDnsClient::async_query(std::string_view name, QueryType type, const OnFinishedCallback& on_finished_cb)
{
    auto query = std::make_shared<Query>(io_strand_, name, type, on_finished_cb);

    //
    // Construct the binary DNS request.
    //

    // TODO: It's not quite clear why res_state is needed for res_nmkquery() which just encodes
    // the DNS query.

#ifdef THREAD_LOCAL_RES_STATE
    // Wrapper for libresolv's res_state to proper init and cleanup
    // the instance (as a thread-local variable).
    struct Res_state {
      struct __res_state res;
      bool initialized = false;

      res_state get() { return &res; }

      Res_state() {
        std::memset(&res, 0, sizeof(res));
        initialized = (res_ninit(&res) == 0);
      }

      ~Res_state() {
        if (initialized) {
          res_nclose(&res);
        }
      }
    };

    thread_local struct Res_state res_wrapper;
    if (!res_wrapper.initialized)
    {
      ERR("res_ninit error: " << *query << ": " << h_errno);
      query->cb(RESULT_ERROR, query->name, query->type, {}, {}, {});
      query->done = true;
      return;
    }

    res_state res = res_wrapper.get();
#else
    struct __res_state res_;
    res_state res = &res_;

    DBG() << "initializing res_state";
    std::memset(&res_, 0, sizeof(res_));
    if (res_ninit(&res_) != 0) {
      ERR() << "res_ninit: " << *query << ": " << h_errno;
      query->cb(RESULT_ERROR, query->name, query->type, {}, {}, {});
      query->done = true;
      return;
    }
#endif

    int req_len = res_nmkquery(
        res,
        ns_o_query,
        query->name.c_str(), ns_c_in, (type == TYPE_A ? ns_t_a : ns_t_aaaa),
        nullptr, 0,
        nullptr,
        query->request.data(), query->request.size());
    if (req_len < 0) {
      ERR() << "res_nmkquery: " << *query << ": " << h_errno;
      query->cb(RESULT_ERROR, query->name, query->type, {}, {}, {});
      query->done = true;
      return;
    }

#ifndef THREAD_LOCAL_RES_STATE
    res_nclose(res);
#endif

    query->request.resize(req_len);
    query->id = ns_get16(query->request.data());

    DBG() << "query " << *query
          << ": name=" << query->name
          << ", type=" << query->type;

    post(io_strand_,
        [this, query]() {
          // Register the query in the map. From now on it must be unregistered after its callback
          // is called.
          queries_[query->id] = query;

          query->timer.expires_after(std::chrono::milliseconds(timeout_ms_));
          query->timer.async_wait(
              boost::asio::bind_executor(io_strand_, [this, query](auto err) {
                if (!err && !query->done) {
                  DBG() << "query " << *query << " timeouted";
                  query->cb(RESULT_TIMEOUT, query->name, query->type, {}, {}, {});
                  query->done = true;
                  queries_.erase(query->id);
                }
                else if (err != boost::asio::error::operation_aborted) {
                  ERR() << "async_wait: " << *query << ": " << err.message();
                }
              }));

          socket_.async_send_to(
              boost::asio::buffer(query->request),
              nameserver_,
              0,
              boost::asio::bind_executor(io_strand_, [this, query](auto err, auto written) {
                if (err) {
                  ERR() << "async_send_to: " << *query << ": " << err.message();

                  if (!query->done) {
                    query->timer.cancel();
                    query->cb(RESULT_ERROR, query->name, query->type, {}, {}, {});
                    query->done = true;
                    queries_.erase(query->id);
                  }
                }
              }));
        });
}

AsyncDnsClient::Query::Query(
        boost::asio::io_context::strand& strand,
        std::string_view name, QueryType type,
        OnFinishedCallback cb)
  : name(name),
    type(type),
    cb(cb),
    timer(strand.context()),
    done(false),
    request(PACKETSZ),
    id(0)
{}

void AsyncDnsClient::start_receiving()
{
    // These are shared instances but it is fine because only a single thread
    // is receiving at a time.
    static unsigned char response[PACKETSZ];
    static boost::asio::ip::udp::endpoint remote;

    socket_.async_receive_from(
        boost::asio::buffer(response),
        remote,
        0,
        boost::asio::bind_executor(io_strand_, [this](auto err, auto received) {
          if (err) {
            if (err != boost::asio::error::operation_aborted) {
              ERR() << "async_receive_from: " << err.message();
            }
            return;
          }

          if (remote != nameserver_) {
            ERR() << "async_receive_from: unexpected endpoint";
            start_receiving();
            return;
          }

          //
          // Parse the binary DNS response.
          //
          ns_msg handle;

          if (ns_initparse(response, received, &handle) != 0) {
            ERR() << "ns_initparse: " << std::strerror(errno);
            start_receiving();
            return;
          }

          auto id = ns_get16(response);
          int rcode = ns_msg_getflag(handle, ns_f_rcode);

          DBG() << "query response: id=" << id
                << ", qr=" << ns_msg_getflag(handle, ns_f_qr)
                << ", aa=" << ns_msg_getflag(handle, ns_f_aa)
                << ", tc=" << ns_msg_getflag(handle, ns_f_tc)
                << ", rcode=" << rcode
                << ", #qd=" << ns_msg_count(handle, ns_s_qd)
                << ", #an=" << ns_msg_count(handle, ns_s_an);

          auto query_it = queries_.find(id);
          if (query_it == queries_.end()) {
            DBG() << "query with id " << id << " not found";
            start_receiving();
            return;
          }

          auto& query = query_it->second;
          if (query->done) {
            DBG() << "query with id " << id << " already timeouted";
            start_receiving();
            return;
          }

          std::vector<std::pair<std::string, boost::asio::ip::address>> addrs;
          std::vector<std::pair<std::string, std::string>> cnames;

          for (std::size_t i = 0; i < ns_msg_count(handle, ns_s_an); ++i) {
            ns_rr rr;

            if (ns_parserr(&handle, ns_s_an, i, &rr) != 0) {
              ERR() << "query " << *query << ": ns_parserr: rr=" << i << ": " << std::strerror(errno);
              continue;
            }

            if (ns_rr_type(rr) == ns_t_cname) {
              char dname[MAXDNAME];

              if (ns_name_uncompress(ns_msg_base(handle), ns_msg_end(handle), ns_rr_rdata(rr),
                                     dname, sizeof(dname)) == -1) {
                ERR() << "query " << *query << ": ns_name_uncompress: rr=" << i << ": " << std::strerror(errno);
                continue;
              }

              cnames.push_back(std::make_pair(ns_rr_name(rr), std::move(dname)));
            }
            else if (ns_rr_type(rr) == ns_t_a) {
              auto addr = boost::asio::ip::address_v4(ns_get32(ns_rr_rdata(rr)));
              addrs.push_back(std::make_pair(ns_rr_name(rr), std::move(addr)));
            }
            else if (ns_rr_type(rr) == ns_t_aaaa) {
              auto addr = boost::asio::ip::address_v6(
                  *reinterpret_cast<const boost::asio::ip::address_v6::bytes_type*>(ns_rr_rdata(rr)));
              addrs.push_back(std::make_pair(ns_rr_name(rr), std::move(addr)));
            }
          }

          query->timer.cancel();
          query->cb(RESULT_SUCCESS, query->name, query->type,
                    rcode, std::move(addrs), std::move(cnames));
          query->done = true;
          queries_.erase(query->id);

          start_receiving();
        }));
}

std::ostream& operator<<(std::ostream& os, const AsyncDnsClient::Query& query)
{
  return os << query.id;
}

std::ostream& operator<<(std::ostream& os, const AsyncDnsClient::QueryType& type)
{
  switch (type) {
    case AsyncDnsClient::QueryType::TYPE_A:
      os << "A";
      break;
    case AsyncDnsClient::QueryType::TYPE_AAAA:
      os << "AAAA";
      break;
  };
  return os;
}

std::ostream& operator<<(std::ostream& os, const AsyncDnsClient::QueryResult& result)
{
  switch (result) {
    case AsyncDnsClient::QueryResult::RESULT_SUCCESS:
      os << "SUCCESS";
      break;
    case AsyncDnsClient::QueryResult::RESULT_TIMEOUT:
      os << "TIMEOUT";
      break;
    case AsyncDnsClient::QueryResult::RESULT_ERROR:
      os << "ERROR";
      break;
  }
  return os;
}
