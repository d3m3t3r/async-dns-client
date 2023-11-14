// logging.h

#pragma once

#include <chrono>
#include <ctime>
#include <thread>
#include <string>
#include <sstream>
#include <iostream>
#include <iomanip>


#define LOG(LEVEL) \
        if (logger().get_threshold() >= (LEVEL)) Logger::Message(logger(), (LEVEL))

#define DBG()   LOG(Logger::Level::DEBUG)
#define INFO()  LOG(Logger::Level::INFO)
#define WARN()  LOG(Logger::Level::WARNING)
#define ERR()   LOG(Logger::Level::ERROR)
#define FATAL() LOG(Logger::Level::FATAL)


//
// Simple poor man's logging
//
// Use with the macros above:
//   INFO() << ...;
// Do not add trailing '\n' or std::endl.
//
class Logger
{
public:
  enum class Level { FATAL = 0, ERROR, WARNING, INFO, DEBUG };

  // Required as forward declaration of the operator as it is used in Message.
  friend std::ostream& operator<<(std::ostream& os, const Logger::Level& level);

  struct Message
  {
    Logger& logger_;
    const Level level_;
    mutable std::ostringstream oss_;

    Message(Logger& logger, Level level)
       : logger_(logger), level_(level)
    {
      //XXX insane way of formatting std::chrono::time_point (...before C++20)
      const auto now = std::chrono::system_clock::now();
      const auto now_ms =
          std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch());
      const auto now_time_t = std::chrono::system_clock::to_time_t(now);
      struct tm now_tm;
      localtime_r(&now_time_t, &now_tm);

      std::ios old_state(nullptr);
      old_state.copyfmt(oss_);

#ifdef USE_STRFTIME
      char buf[80];
      std::strftime(buf, sizeof(buf), "%b %d %T", &now_tm);
      oss_ << buf << "."
#else
      oss_ << std::put_time(&now_tm, "%b %d %T") << "."
#endif
           << std::setfill('0') << std::setw(3) << now_ms.count() % 1000
           << " [" << std::hex << std::this_thread::get_id() << "] "
           << level_ << ": ";
       oss_.copyfmt(old_state);
    }

    ~Message()
    {
      // Not quite atomic but usually good enough.
      oss_ << "\n";
      logger_.os() << oss_.str();
    }
  };

  Logger(Level threshold = Level::FATAL, bool use_stderr = true)
      : threshold_(threshold), os_(use_stderr ? std::cerr : std::cout)
  {}

  void set_threshold(Level threshold) { threshold_ = threshold; }
  Level get_threshold() const { return threshold_; }

private:
  std::ostream& os() const { return os_; }

  Level threshold_;
  std::ostream& os_;
};

inline std::ostream& operator<<(std::ostream& os, const Logger::Level& level)
{
  static const char* names[] = { "FATAL", "ERROR", "WARNING", "INFO", "DEBUG" };
  return os << names[(unsigned int)level >= std::size(names) ? std::size(names) - 1 : (unsigned int)level];
}

template<typename T>
const Logger::Message& operator<<(const Logger::Message& msg, const T& t)
{
  msg.oss_ << t;
  return msg;
}

[[maybe_unused]] static Logger& logger()
{
  static Logger logger;
  return logger;
}
