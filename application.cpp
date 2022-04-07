/**
 *
 * @author Ayaan Khan
 *
 *
 * -- Implement GO Back-N and Selective Repeat Sliding Window Protocols.
 *
 */

#include "xlogger.hpp"
#include <algorithm>
#include <atomic>
#include <chrono>
#include <fstream>
#include <iostream>
#include <memory>
#include <mutex>
#include <queue>
#include <random>
#include <thread>
#include <type_traits>
#include <unordered_map>
#include <vector>

enum packet_status { NOT_SENT, IN_TRANSIT, SENT };

const std::string DEFAULT_SENDER = "0.0.0.0";
const std::string DEFAULT_RECIVER = "1.1.1.1";
bool stop_simulation = false;

class random_number_genrator {
public:
  random_number_genrator() = default;
  ~random_number_genrator() = default;
  int get_random_in_range(int _l, int _r) {
    std::random_device rd;
    std::mt19937_64 generator(rd());
    std::uniform_int_distribution<int> random_distribution(_l, _r);
    return random_distribution(generator);
  }
};

class packet {
private:
  int id;
  int timeout;
  bool is_acknowledged;
  packet_status status;

public:
  packet() {}

  packet(int _id, int _timeout, bool _is_acknowledged)
      : id(_id), timeout(_timeout), is_acknowledged(_is_acknowledged),
        status(packet_status::NOT_SENT) {}

  ~packet() {}

  constexpr inline int get_id() const { return this->id; }

  constexpr inline int get_timeout() const { return this->timeout; }

  constexpr inline bool get_ack_status() const { return this->is_acknowledged; }

  constexpr inline packet_status get_status() const { return this->status; }

  void set_id(int _id) { id = _id; }

  void set_timeout(int _timeout) { timeout = _timeout; }

  void set_ack_status(bool _ack_status) { is_acknowledged = _ack_status; }

  void set_packet_status(packet_status _status) { status = _status; }
};

class random_packet_generator {
public:
  random_packet_generator() = default;
  ~random_packet_generator() = default;
  std::vector<packet> generate_random_packets(int packet_count);
};

std::vector<packet>
random_packet_generator::generate_random_packets(int packet_count) {
  std::vector<packet> packets;
  std::vector<int> packet_ids(packet_count);
  for (int i = 0; i < packet_count; i++) {
    packet_ids[i] = i;
  }

  int timeout = 50;
  for (auto &packet_id : packet_ids) {
    packets.push_back(std::move(packet(packet_id, timeout, false)));
    timeout += 50;
  }
  return packets;
}

class semaphore {
private:
  bool s;

public:
  semaphore(bool _s = false) : s(_s) {}

  ~semaphore() = default;

  inline void release_lock() { s = false; }

  inline void wait_and_lock() {
    while (s)
      ;
    s = true;
  }
};

class transmission_channel {
private:
  semaphore s;
  std::queue<packet> channel_queue;

public:
  transmission_channel() { s = semaphore(); };

  ~transmission_channel() = default;

  std::queue<packet> *get_channel() { return &(this->channel_queue); }

  inline semaphore *get_semaphore() { return &s; }

  void log_channel() {
    std::queue<packet> tmp = channel_queue;
    while (!tmp.empty()) {
      DEBUG_X_LOG("[CHANNEL] IN-TRANSIT packet id: ", tmp.front().get_id());
      tmp.pop();
    }
  }
};

class timer {
private:
  int64_t instant;

public:
  timer() { instant = int64_t(); }

  ~timer() = default;

  inline void update_timer() {
    while (!stop_simulation) {
      std::this_thread::sleep_for(std::chrono::milliseconds(1000));
      CRITICAL_X_LOG("[TIMER] updating timer ", instant);
      instant += 50;
    }
  }

  constexpr inline int64_t get_timer_instant() const { return instant; }
};

class GBN_core {
private:
  int n;
  std::unordered_map<int, bool> lost_packets;
  transmission_channel *channel;
  timer *t;
  std::queue<int> ack_reciept;
  semaphore s_ack;

public:
  GBN_core() = default;

  explicit GBN_core(int _n) : n(_n) {
    channel = new transmission_channel();
    t = new timer();
    ack_reciept = std::queue<int>();
    s_ack = semaphore();
  }

  ~GBN_core() = default;

  constexpr inline int get_window_size() const { return this->n; }

  inline transmission_channel *get_transmission_channel() {
    return this->channel;
  }

  inline std::queue<int> *get_ack_queue_handle() {
    return &(this->ack_reciept);
  }

  inline timer *get_timer() { return this->t; }

  inline void run_timer() {
    // std::this_thread::sleep_for(std::chrono::milliseconds(1000));
    t->update_timer();
  }

  inline semaphore *get_ack_semaphore() { return &s_ack; }

  inline std::unordered_map<int, bool> *get_lost_packets_handle() {
    return &(this->lost_packets);
  }
};

class GBN_sender {
private:
  std::vector<packet> packets;
  GBN_core *gbn_core;
  int lp;
  int rp;

public:
  GBN_sender() = default;

  GBN_sender(GBN_core *_gbn_core, int _packet_count) : gbn_core(_gbn_core) {
    random_packet_generator rpg;
    packets = rpg.generate_random_packets(_packet_count);
    lp = 0;
    rp = gbn_core->get_window_size() - 1;
  }

  ~GBN_sender() = default;

  void run();
  void load_packets_on_channel();
  void accept_acknowledgement(int &);
  void handle_retransmission();
};

void GBN_sender::run() {
  INFO_X_LOG("[SENDER ", DEFAULT_SENDER, "] Packets for transmission are --- ");
  for (int i = 0; i < packets.size(); i++) {
    DEBUG_X_LOG("[SENDER ", DEFAULT_SENDER,
                "] packet_id: ", packets[i].get_id(),
                " timeout: ", packets[i].get_timeout(),
                "ms acknowledgement: ", packets[i].get_ack_status(),
                " status: ", packets[i].get_status());
  }

  int sent_packets = 0, total_packets = packets.size();
  DEBUG_X_LOG("[SENDER ", DEFAULT_SENDER, "] sent packets: ", sent_packets,
              " total packets:", total_packets);
  while (sent_packets < total_packets) {
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    load_packets_on_channel();

    accept_acknowledgement(sent_packets);

    handle_retransmission();
  }
  DEBUG_X_LOG("[SENDER ", DEFAULT_SENDER, "] sent packets: ", sent_packets,
              " total packets:", total_packets);
}

void GBN_sender::load_packets_on_channel() {
  static const int n = gbn_core->get_window_size();

  while (rp - lp >= 0 && rp - lp < n && lp < packets.size()) {
    if (packets[lp].get_status() != packet_status::SENT ||
        packets[lp].get_ack_status() == false) {

      gbn_core->get_transmission_channel()->get_semaphore()->wait_and_lock();
      DEBUG_X_LOG("[SENDER ", DEFAULT_SENDER, "] Loading packet with id ",
                  packets[lp].get_id(), " on transmission channel");

      gbn_core->get_transmission_channel()->get_channel()->push(packets[lp]);
      packets[lp].set_packet_status(packet_status::IN_TRANSIT);
      gbn_core->get_transmission_channel()->get_semaphore()->release_lock();
    }
    lp++;
  }
  rp += n;
  if (rp >= packets.size())
    rp = packets.size();
  DEBUG_X_LOG("[SENDER ", DEFAULT_SENDER, "] Packets IN-TRANSIT are: ");
  gbn_core->get_transmission_channel()->log_channel();
}

void GBN_sender::accept_acknowledgement(int &sent_packets) {
  gbn_core->get_ack_semaphore()->wait_and_lock();
  while (!gbn_core->get_ack_queue_handle()->empty()) {
    int current_ack_id = gbn_core->get_ack_queue_handle()->front();
    DEBUG_X_LOG("[SENDER ", DEFAULT_SENDER,
                "] Accepting acknowledgement for packet id: ", current_ack_id);
    for (auto &packet : packets) {
      if (packet.get_id() == current_ack_id) {
        packet.set_ack_status(true);
        packet.set_packet_status(packet_status::SENT);
        sent_packets++;
        break;
      }
    }
    gbn_core->get_ack_queue_handle()->pop();
  }
  gbn_core->get_ack_semaphore()->release_lock();
}

void GBN_sender::handle_retransmission() {
  int current_time_instant = gbn_core->get_timer()->get_timer_instant();

  for (int i = 0; i < packets.size(); i++) {
    packet current_packet = packets[i];

    if ((current_packet.get_timeout() <= current_time_instant &&
         (current_packet.get_status() != packet_status::SENT &&
          current_packet.get_ack_status() == false))) {
      lp = i, rp = i + gbn_core->get_window_size() - 1;
      DEBUG_X_LOG("[SENDER ", DEFAULT_SENDER,
                  "] Retransmitting packets in window [", lp, ",", rp, "]");
      load_packets_on_channel();
      break;
    }
  }
}

class GBN_reciver {
private:
  std::vector<packet> recived_packets;
  int expected_packet;
  GBN_core *gbn_core;
  int total_packets;
  std::vector<int> dispatch_container;
  int ack_time_instant;

public:
  GBN_reciver() = default;

  GBN_reciver(GBN_core *_gbn_core, int _total_packets,
              int _ack_time_instant = 0)
      : gbn_core(_gbn_core), total_packets(_total_packets),
        ack_time_instant(_ack_time_instant), expected_packet(0) {
    dispatch_container = std::vector<int>();
    random_number_genrator rng;
    int lost_packets_count =
        rng.get_random_in_range(0, ceil(total_packets / 6.0));
    INFO_X_LOG("[RECIVER ", DEFAULT_RECIVER, "] Corrupted packets --- ");
    for (int i = 0; i < lost_packets_count; i++) {
      int lost_packet_id = rng.get_random_in_range(0, total_packets);
      INFO_X_LOG("[RECIVER ", DEFAULT_RECIVER,
                 "] corrupted packet id: ", lost_packet_id);
      (*(gbn_core->get_lost_packets_handle()))[lost_packet_id] = true;
    }
  }

  ~GBN_reciver() = default;

  void run();
  void accept_packets_from_channel(transmission_channel *channel);
  void dispatch_ack();
};

void GBN_reciver::run() {
  transmission_channel *channel = gbn_core->get_transmission_channel();

  while (recived_packets.size() < total_packets) {
    DEBUG_X_LOG("[RECIVER ", DEFAULT_RECIVER,
                "] Recived packets: ", recived_packets.size(),
                " Total packets: ", total_packets);
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    accept_packets_from_channel(channel);

    int current_time_instant = gbn_core->get_timer()->get_timer_instant();
    INFO_X_LOG("[RECIVER ", DEFAULT_RECIVER,
               "] Current time instant: ", current_time_instant,
               "ms Acknowledgement time instant: ", ack_time_instant, "ms");
    if (current_time_instant >= ack_time_instant)
      dispatch_ack();
    ack_time_instant += ack_time_instant;
  }
  DEBUG_X_LOG("[RECIVER ", DEFAULT_RECIVER,
              "] Recived packets: ", recived_packets.size(),
              " Total packets: ", total_packets);
  stop_simulation = true;
}

void GBN_reciver::accept_packets_from_channel(transmission_channel *t_channel) {
  t_channel->get_semaphore()->wait_and_lock();
  std::queue<packet> *channel = t_channel->get_channel();
  while (!channel->empty()) {
    packet currently_arrived_packet = channel->front();
    int currently_arrived_packet_id = currently_arrived_packet.get_id();
    DEBUG_X_LOG("[RECIVER ", DEFAULT_RECIVER, "] Reciving packet ",
                currently_arrived_packet_id,
                " Expected packet: ", expected_packet);
    if (((*(gbn_core
                ->get_lost_packets_handle()))[currently_arrived_packet_id]) ||
        currently_arrived_packet_id != expected_packet) {
      (*(gbn_core->get_lost_packets_handle()))[currently_arrived_packet_id] =
          false;
      while (!channel->empty() &&
             currently_arrived_packet.get_id() != expected_packet) {
        DEBUG_X_LOG("[RECIVER ", DEFAULT_RECIVER,
                    "] Discarding packet (corrupted / unexpected) ",
                    channel->front().get_id());
        channel->pop();
        currently_arrived_packet = channel->front();
      }
    }
    if (currently_arrived_packet_id == expected_packet) {
      DEBUG_X_LOG("[RECIVER ", DEFAULT_RECIVER, "] Accepting packet ",
                  currently_arrived_packet_id);
      expected_packet++;
      recived_packets.push_back(currently_arrived_packet);
      channel->pop();
      dispatch_container.push_back(currently_arrived_packet_id);
    }
  }
  t_channel->get_semaphore()->release_lock();
}

void GBN_reciver::dispatch_ack() {
  gbn_core->get_ack_semaphore()->wait_and_lock();
  for (int i = 0; i < dispatch_container.size(); i++) {
    DEBUG_X_LOG("[RECIVER ", DEFAULT_RECIVER,
                "] Dispatching acknowledgement for packet id ",
                dispatch_container[i]);
    gbn_core->get_ack_queue_handle()->push(dispatch_container[i]);
  }
  gbn_core->get_ack_semaphore()->release_lock();
  dispatch_container.clear();
}

class SR_core {
private:
  int n;
  std::unordered_map<int, bool> lost_packets;
  transmission_channel *channel;
  timer *t;
  std::queue<int> ack_reciept;
  semaphore s_ack;

public:
  SR_core() = default;

  explicit SR_core(int _n) : n(_n) {
    channel = new transmission_channel();
    t = new timer();
    ack_reciept = std::queue<int>();
    s_ack = semaphore();
  }

  ~SR_core() = default;

  constexpr inline int get_window_size() const { return this->n; }

  inline transmission_channel *get_transmission_channel() {
    return this->channel;
  }

  inline std::queue<int> *get_ack_queue_handle() {
    return &(this->ack_reciept);
  }

  inline timer *get_timer() { return this->t; }

  inline void run_timer() {
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    t->update_timer();
  }

  inline semaphore *get_ack_semaphore() { return &s_ack; }

  inline std::unordered_map<int, bool> *get_lost_packets_handle() {
    return &(this->lost_packets);
  }
};

class SR_sender {
private:
  std::vector<packet> packets;
  SR_core *sr_core;
  int lp;
  int rp;

public:
  SR_sender() = default;

  SR_sender(SR_core *_sr_core, int _packet_count) : sr_core(_sr_core) {
    random_packet_generator rpg;
    packets = rpg.generate_random_packets(_packet_count);
    lp = 0;
    rp = sr_core->get_window_size() - 1;
  }

  ~SR_sender() = default;

  void run();
  void load_packets_on_channel();
  void accept_acknowledgement(int &);
  void handle_retransmission();
};

void SR_sender::run() {
  INFO_X_LOG("[SENDER ", DEFAULT_SENDER, "] Packets for transmission are --- ");
  for (int i = 0; i < packets.size(); i++) {
    DEBUG_X_LOG("[SENDER ", DEFAULT_SENDER,
                "] packet_id: ", packets[i].get_id(),
                " timeout: ", packets[i].get_timeout(),
                "ms acknowledgement: ", packets[i].get_ack_status(),
                " status: ", packets[i].get_status());
  }

  int sent_packets = 0, total_packets = packets.size();
  DEBUG_X_LOG("[SENDER ", DEFAULT_SENDER, "] sent packets: ", sent_packets,
              " total packets:", total_packets);
  while (sent_packets < total_packets) {
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    load_packets_on_channel();

    accept_acknowledgement(sent_packets);

    handle_retransmission();
  }
  DEBUG_X_LOG("[SENDER ", DEFAULT_SENDER, "] sent packets: ", sent_packets,
              " total packets:", total_packets);
}

void SR_sender::load_packets_on_channel() {
  const int n = sr_core->get_window_size();

  while (rp - lp >= 0 && rp - lp + 1 <= n && lp < packets.size()) {
    if (packets[lp].get_status() != packet_status::SENT ||
        packets[lp].get_ack_status() == false) {
      sr_core->get_transmission_channel()->get_semaphore()->wait_and_lock();
      DEBUG_X_LOG("[SENDER ", DEFAULT_SENDER, "] Loading packet with id ",
                  packets[lp].get_id(), " on transmission channel");
      sr_core->get_transmission_channel()->get_channel()->push(packets[lp]);
      packets[lp].set_packet_status(packet_status::IN_TRANSIT);
      sr_core->get_transmission_channel()->get_semaphore()->release_lock();
    }
    lp++;
  }
  rp += n;
  if (rp > packets.size())
    rp = packets.size() - 1;
  DEBUG_X_LOG("[SENDER ", DEFAULT_SENDER, "] Packets IN-TRANSIT are: ");
  sr_core->get_transmission_channel()->log_channel();
}

void SR_sender::accept_acknowledgement(int &sent_packets) {
  sr_core->get_ack_semaphore()->wait_and_lock();
  while (!sr_core->get_ack_queue_handle()->empty()) {
    int current_ack_id = sr_core->get_ack_queue_handle()->front();
    DEBUG_X_LOG("[SENDER ", DEFAULT_SENDER,
                "] Accepting acknowledgement for packet id: ", current_ack_id);
    for (auto &packet : packets) {
      if (packet.get_id() == current_ack_id) {
        packet.set_ack_status(true);
        packet.set_packet_status(packet_status::SENT);
        sent_packets++;
        break;
      }
    }
    sr_core->get_ack_queue_handle()->pop();
  }
  sr_core->get_ack_semaphore()->release_lock();
}

void SR_sender::handle_retransmission() {
  int current_time_instant = sr_core->get_timer()->get_timer_instant();

  for (int i = 0; i < packets.size(); i++) {
    packet *current_packet = &packets[i];

    if ((current_packet->get_timeout() <= current_time_instant &&
         (current_packet->get_status() != packet_status::SENT &&
          current_packet->get_ack_status() == false))) {
      DEBUG_X_LOG("[SENDER ", DEFAULT_SENDER,
                  "] Retransmitting packet with id ", current_packet->get_id());
      sr_core->get_transmission_channel()->get_semaphore()->wait_and_lock();
      DEBUG_X_LOG("[SENDER ", DEFAULT_SENDER, "] Loading packet with id ",
                  current_packet->get_id(), " on transmission channel");
      sr_core->get_transmission_channel()->get_channel()->push(*current_packet);
      current_packet->set_packet_status(packet_status::IN_TRANSIT);
      sr_core->get_transmission_channel()->get_semaphore()->release_lock();
      break;
    }
  }
}

class SR_reciver {
private:
  std::vector<packet> recived_packets;
  SR_core *sr_core;
  int total_packets;
  std::vector<int> dispatch_container;
  int ack_time_instant;

public:
  SR_reciver() = default;

  SR_reciver(SR_core *_sr_core, int _total_packets, int _ack_time_instant = 0)
      : sr_core(_sr_core), total_packets(_total_packets),
        ack_time_instant(_ack_time_instant) {
    dispatch_container = std::vector<int>();
    random_number_genrator rng;
    int lost_packets_count =
        rng.get_random_in_range(0, ceil(total_packets / 6.0));
    INFO_X_LOG("[RECIVER ", DEFAULT_RECIVER, "] Corrupted packets --- ");
    for (int i = 0; i < lost_packets_count; i++) {
      int lost_packet_id = rng.get_random_in_range(0, total_packets);
      INFO_X_LOG("[RECIVER ", DEFAULT_RECIVER,
                 "] corrupted packet id: ", lost_packet_id);
      (*(sr_core->get_lost_packets_handle()))[lost_packet_id] = true;
    }
  }

  ~SR_reciver() = default;

  void run();
  void accept_packets_from_channel(transmission_channel *channel);
  void dispatch_ack();
};

void SR_reciver::run() {
  transmission_channel *channel = sr_core->get_transmission_channel();
  while (recived_packets.size() < total_packets) {
    DEBUG_X_LOG("[RECIVER ", DEFAULT_RECIVER,
                "] Recived packets: ", recived_packets.size(),
                " Total packets: ", total_packets);
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    accept_packets_from_channel(channel);

    int current_time_instant = sr_core->get_timer()->get_timer_instant();
    INFO_X_LOG("[RECIVER ", DEFAULT_RECIVER,
               "] Current time instant: ", current_time_instant,
               "ms Acknowledgement time instant: ", ack_time_instant, "ms");

    if (current_time_instant >= ack_time_instant)
      dispatch_ack();
    ack_time_instant += ack_time_instant;
  }
  DEBUG_X_LOG("[RECIVER ", DEFAULT_RECIVER,
              "] Recived packets: ", recived_packets.size(),
              " Total packets: ", total_packets);
  stop_simulation = true;
}

void SR_reciver::accept_packets_from_channel(transmission_channel *t_channel) {

  t_channel->get_semaphore()->wait_and_lock();
  std::queue<packet> *channel = t_channel->get_channel();
  while (!channel->empty()) {
    packet currently_arrived_packet = channel->front();
    int currently_arrived_packet_id = currently_arrived_packet.get_id();
    DEBUG_X_LOG("[RECIVER ", DEFAULT_RECIVER, "] Reciving packet ",
                currently_arrived_packet_id);

    if (((*(sr_core
                ->get_lost_packets_handle()))[currently_arrived_packet_id])) {
      (*(sr_core->get_lost_packets_handle()))[currently_arrived_packet_id] =
          false;
      DEBUG_X_LOG("[RECIVER ", DEFAULT_RECIVER,
                  "] Discarding packet (corrupted / unexpected) ",
                  currently_arrived_packet_id);
    } else {
      DEBUG_X_LOG("[RECIVER ", DEFAULT_RECIVER, "] Accepting packet ",
                  currently_arrived_packet_id);
      recived_packets.push_back(currently_arrived_packet);
      dispatch_container.push_back(currently_arrived_packet_id);
    }
    channel->pop();
  }
  t_channel->get_semaphore()->release_lock();
}

void SR_reciver::dispatch_ack() {
  sr_core->get_ack_semaphore()->wait_and_lock();
  for (int i = 0; i < dispatch_container.size(); i++) {
    DEBUG_X_LOG("[RECIVER ", DEFAULT_RECIVER,
                "] Dispatching acknowledgement for packet id ",
                dispatch_container[i]);
    sr_core->get_ack_queue_handle()->push(dispatch_container[i]);
  }
  sr_core->get_ack_semaphore()->release_lock();
  dispatch_container.clear();
}

class test_gbn {
public:
  test_gbn() = default;
  ~test_gbn() = default;

  void simulate() {
    stop_simulation = false;
    int window_size = 4, packet_count = 10;
    GBN_core gbn(window_size);
    GBN_sender gbn_sender(&gbn, packet_count);
    GBN_reciver gbn_reciver(&gbn, packet_count);

    std::thread gbn_main(&GBN_core::run_timer, gbn);
    std::thread reciver(&GBN_reciver::run, gbn_reciver);
    std::thread sender(&GBN_sender::run, gbn_sender);

    gbn_main.join();
    sender.join();
    reciver.join();
  }
};

class test_sr {
public:
  test_sr() = default;

  ~test_sr() = default;

  void simulate() {
    stop_simulation = false;
    int window_size = 4, packet_count = 10;

    SR_core sr(window_size);
    SR_sender sr_sender(&sr, packet_count);
    SR_reciver sr_reciver(&sr, packet_count);

    std::thread sr_main(&SR_core::run_timer, sr);
    std::thread sender(&SR_sender::run, sr_sender);
    std::thread reciver(&SR_reciver::run, sr_reciver);

    sr_main.join();
    sender.join();
    reciver.join();
  }
};

int main() {
  xlogger::init_xlogger();

  INFO_X_LOG("----------------TRACING GBN ALGORITHM-----------------------");
  test_gbn t_gbn;
  t_gbn.simulate();

  INFO_X_LOG("---------------TRACING SR ALGORITHM------------------------");
  test_sr t_sr;
  t_sr.simulate();

  xlogger::destroy_xlogger();
  return 0;
}
