/**
 *
 * MIT License
 *
 * Copyright (c) 2021 Ayaan Khan
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 */

#pragma once

#include <array>
#include <chrono>
#include <cstdarg>
#include <cstddef>
#include <ctime>
#include <deque>
#include <fstream>
#include <iostream>
#include <list>
#include <map>
#include <mutex>
#include <ostream>
#include <set>
#include <sstream>
#include <string>
#include <type_traits>
#include <unordered_map>
#include <utility>
#include <vector>

namespace xlogger {
enum xlogger_color {
  _RESET,
  _BLACK,
  _RED,
  _GREEN,
  _YELLOW,
  _BLUE,
  _MAGENTA,
  _CYAN,
  _WHITE,
  _BOLD_BLACK,
  _BOLD_RED,
  _BOLD_GREEN,
  _BOLD_YELLOW,
  _BOLD_BLUE,
  _BOLD_MAGENTA,
  _BOLD_CYAN,
  _BOLD_WHITE
};

enum xlogger_log_level { _INFO, _DEBUG, _WARN, _CRITICAL, _ERROR, _FATAL };

enum xlogger_type { _FILE, _CONSOLE };

class xlogger_core {
private:
  xlogger_log_level _log_level;
  std::unordered_map<xlogger_color, std::string> _xlogger_color_map;

public:
  xlogger_core() : _log_level(xlogger_log_level::_INFO) {
    _xlogger_color_map[_RESET] = "\033[0m";
    _xlogger_color_map[_BLACK] = "\033[30m";
    _xlogger_color_map[_RED] = "\033[31m";
    _xlogger_color_map[_GREEN] = "\033[32m";
    _xlogger_color_map[_YELLOW] = "\033[33m";
    _xlogger_color_map[_BLUE] = "\033[34m";
    _xlogger_color_map[_MAGENTA] = "\033[35m";
    _xlogger_color_map[_CYAN] = "\033[36m";
    _xlogger_color_map[_WHITE] = "\033[37m";
    _xlogger_color_map[_BOLD_BLACK] = "\033[1m\033[30m";
    _xlogger_color_map[_BOLD_RED] = "\033[1m\033[31m";
    _xlogger_color_map[_BOLD_GREEN] = "\033[1m\033[32m";
    _xlogger_color_map[_BOLD_YELLOW] = "\033[1m\033[33m";
    _xlogger_color_map[_BOLD_BLUE] = "\033[1m\033[34m";
    _xlogger_color_map[_BOLD_MAGENTA] = "\033[1m\033[35m";
    _xlogger_color_map[_BOLD_CYAN] = "\033[1m\033[36m";
    _xlogger_color_map[_BOLD_WHITE] = "\033[1m\033[37m";
  }

  virtual ~xlogger_core() {}

  constexpr inline xlogger_log_level get_log_level() const {
    return this->_log_level;
  }

  virtual inline void set_log_level(const xlogger_log_level &log_level) {
    this->_log_level = log_level;
  }

  inline const std::string &get_xlogger_color(const xlogger_color &color) {
    return this->_xlogger_color_map[color];
  }

  const std::string get_timestamp() const {
    auto current_instant = std::chrono::system_clock::now();
    auto current_instant_time_t =
        std::chrono::system_clock::to_time_t(current_instant);
    const char *x = std::ctime(&current_instant_time_t);
    std::string timestamp;
    for (int i = 0; x[i] != '\n'; i++)
      timestamp.push_back(x[i]);
    return timestamp;
  }
};

template <typename T>
std::ostream &operator<<(std::ostream &os, const std::vector<T> &vec) {
  os << "[";
  for (decltype(vec.size()) i = 0; i < vec.size(); ++i) {
    os << vec[i];
    if (i != vec.size() - 1)
      os << ", ";
  }
  os << "]\n";
  return os;
}

template <typename T>
std::ostream &operator<<(std::ostream &os, const std::list<T> &l) {
  os << "[";
  for (decltype(l.size()) i = 0; i < l.size(); ++i) {
    os << l.front();
    if (i != l.size() - 1)
      os << ", ";
  }
  os << "]\n";
  return os;
}

template <typename K, typename V>
std::ostream &operator<<(std::ostream &os,
                         const std::unordered_map<K, V> &hash_map) {
  os << "[";
  for (auto k_v_iterator_pair = hash_map.begin();
       k_v_iterator_pair != hash_map.end();) {
    os << k_v_iterator_pair->first << ": " << k_v_iterator_pair->second;
    if (++k_v_iterator_pair != hash_map.end()) {
      os << ", ";
    }
  }
  os << "]\n";
  return os;
}

template <typename K, typename V>
std::ostream &operator<<(std::ostream &os, const std::map<K, V> &m) {
  os << "[";
  for (auto k_v_iterator_pair = m.begin(); k_v_iterator_pair != m.end();) {
    os << k_v_iterator_pair->first << ": " << k_v_iterator_pair->second;
    if (++k_v_iterator_pair != m.end()) {
      os << ", ";
    }
  }
  os << "]\n";
  return os;
}

class xfile_logger : public xlogger_core {
private:
  std::ofstream *_file_handler;
  std::string _filepath;

  template <typename Args> constexpr void log(Args &&arg) const {
    *_file_handler << std::forward<decltype(arg)>(arg);
  }

public:
  xfile_logger() { _file_handler = new std::ofstream(); }

  explicit xfile_logger(const std::string &filepath) : _filepath(filepath) {
    _file_handler = new std::ofstream();
    _file_handler->open(_filepath);
  }

  explicit xfile_logger(xfile_logger &xf) {
    this->_file_handler = xf._file_handler;
    this->_filepath = xf._filepath;
  }

  virtual ~xfile_logger() {
    if (_file_handler->is_open())
      _file_handler->close();
  }

  template <typename... Args>
  constexpr void logger(const std::string &log_reference,
                        Args &&...args) const {
    log(log_reference);
    switch (get_log_level()) {
    case _INFO:
      log("[INFO");
      break;

    case _DEBUG:
      log("DEBUG");
      break;

    case _WARN:
      log("[WARN");
      break;

    case _CRITICAL:
      log("[CRITICAL");
      break;

    case _ERROR:
      log("[ERROR");
      break;

    case _FATAL:
      log("[FATAL");
      break;

    default:
      log("-- [INFO");
      break;
    }
    log(": " + get_timestamp() + "] ");
    (log(std::forward<Args>(args)), ...);
    log("\n");
  }
};

class xconsole_logger : public xlogger_core {
private:
public:
  xconsole_logger() {}
  virtual ~xconsole_logger() {}

  template <typename Args> void log(Args &&arg) const {
    std::cout << std::forward<decltype(arg)>(arg);
  }

  template <typename... Args>
  void logger(const std::string &log_reference, Args &&...args) {
    log(log_reference);
    switch (get_log_level()) {
    case _INFO:
      log(get_xlogger_color(_GREEN) + "[INFO");
      break;

    case _DEBUG:
      log(get_xlogger_color(_CYAN) + "[DEBUG");
      break;

    case _WARN:
      log(get_xlogger_color(_YELLOW) + "[WARN");
      break;

    case _CRITICAL:
      log(get_xlogger_color(_MAGENTA) + "[CRITICAL");
      break;

    case _ERROR:
      log(get_xlogger_color(_RED) + "[ERROR");
      break;

    case _FATAL:
      log(get_xlogger_color(_BOLD_RED) + "[FATAL");
      break;

    default:
      log(get_xlogger_color(_GREEN) + "[INFO");
      break;
    }
    log(": " + get_timestamp() + "] ");
    (log(std::forward<Args>(args)), ...);
    log("\n" + get_xlogger_color(_RESET));
  }
};

class xlogger : private xfile_logger, private xconsole_logger {
private:
  static xlogger *_logger;
  bool _type_console;
  bool _type_file;
  std::mutex _mtx;

public:
  xlogger() : xfile_logger(), _type_console(true), _type_file(false) {}

  explicit xlogger(const std::string &filepath)
      : xfile_logger(filepath), _type_console(true), _type_file(true) {}

  virtual ~xlogger() {}

  constexpr inline bool get_type_file() const { return this->_type_file; }

  constexpr inline void set_type_file(bool type_file) {
    this->_type_file = type_file;
  }

  constexpr inline bool get_type_console() const { return this->_type_console; }

  constexpr inline void set_type_console(bool type_console) {
    this->_type_console = type_console;
  }

  static xlogger *get_logger() {
    if (!_logger)
      _logger = new xlogger();
    return _logger;
  }

  static xlogger *get_logger(const std::string &filepath) {
    if (!_logger)
      _logger = new xlogger(filepath);
    return _logger;
  }

  template <typename... Args>
  void logger(const char *file, const int line,
              const xlogger_log_level &log_level, Args &&...args) {
    const std::string log_reference(
        xconsole_logger::get_xlogger_color(xlogger_color::_BOLD_YELLOW) + file +
        std::string(": ") + std::to_string(line) + std::string(" -- ") +
        xconsole_logger::get_xlogger_color(xlogger_color::_RESET));
    std::lock_guard<std::mutex> locker(_mtx);
    if (_type_file) {
      xfile_logger::set_log_level(log_level);
      xfile_logger::logger(log_reference, args...);
    }
    if (_type_console) {
      xconsole_logger::set_log_level(log_level);
      xconsole_logger::logger(log_reference, args...);
    }
  }
};

xlogger *init_xlogger() { return xlogger::get_logger(); }

xlogger *init_xlogger(const std::string &filepath) {
  return xlogger::get_logger(filepath);
}

void destroy_xlogger() {
  if (xlogger::xlogger::get_logger())
    delete xlogger::xlogger::get_logger();
}
} // namespace xlogger

xlogger::xlogger *xlogger::xlogger::_logger = nullptr;

#define INFO_X_LOG(...)                                                        \
  xlogger::xlogger::get_logger()->logger(                                      \
      __FILE__, __LINE__, xlogger::xlogger_log_level::_INFO, __VA_ARGS__)

#define DEBUG_X_LOG(...)                                                       \
  xlogger::xlogger::get_logger()->logger(                                      \
      __FILE__, __LINE__, xlogger::xlogger_log_level::_DEBUG, __VA_ARGS__)

#define WARN_X_LOG(...)                                                        \
  xlogger::xlogger::get_logger()->logger(                                      \
      __FILE__, __LINE__, xlogger::xlogger_log_level::_WARN, __VA_ARGS__)

#define CRITICAL_X_LOG(...)                                                    \
  xlogger::xlogger::get_logger()->logger(                                      \
      __FILE__, __LINE__, xlogger::xlogger_log_level::_CRITICAL, __VA_ARGS__)

#define ERROR_X_LOG(...)                                                       \
  xlogger::xlogger::get_logger()->logger(                                      \
      __FILE__, __LINE__, xlogger::xlogger_log_level::_ERROR, __VA_ARGS__)

#define FATAL_X_LOG(...)                                                       \
  xlogger::xlogger::get_logger()->logger(xlogger::xlogger_log_level::_FATAL,   \
                                         __VA_ARGS__)
